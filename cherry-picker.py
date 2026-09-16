import argparse
import multiprocessing
import os
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict

DB_NAME = "git_hashes.db"
CHERRY_PICK_RE = re.compile(r"\(cherry picked from commit ([a-fA-F0-9]{40})\)")
CHUNK_SIZE = 2000  # Number of commits per worker task


class DisjointSet:
    """Fast, iterative Union-Find with path compression (stack-safe)."""

    def __init__(self):
        self.parent = {}

    def find(self, item: str) -> str:
        if item not in self.parent:
            self.parent[item] = item
            return item

        root = item
        while root != self.parent[root]:
            root = self.parent[root]

        curr = item
        while curr != root:
            nxt = self.parent[curr]
            self.parent[curr] = root
            curr = nxt

        return root

    def union(self, item1: str, item2: str):
        root1 = self.find(item1)
        root2 = self.find(item2)
        if root1 != root2:
            self.parent[root1] = root2


def run_git(cmd: list[str], cwd: str = ".") -> str:
    res = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, errors="replace", check=True
    )
    return res.stdout.strip()


def init_db(conn: sqlite3.Connection):
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hashes (
                hash_value BLOB NOT NULL PRIMARY KEY CHECK(length(hash_value) = 20),
                group_id INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_hashes_group ON hashes(group_id);

            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)


def get_last_processed_commit(conn: sqlite3.Connection, repo_path: str) -> str | None:
    cur = conn.cursor()
    cur.execute("SELECT value FROM state WHERE key = 'last_commit'")
    row = cur.fetchone()
    if not row:
        return None

    last_sha = row[0]
    try:
        subprocess.run(
            ["git", "cat-file", "-e", f"{last_sha}^{{commit}}"],
            cwd=repo_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return last_sha
    except subprocess.CalledProcessError:
        print(f"Warning: Checkpointed commit {last_sha[:10]} no longer exists. Starting fresh scan.")
        return None


def get_commit_list(repo_path: str, rev_spec: str) -> list[str]:
    """Returns an ordered list of full 40-character commit SHAs."""
    try:
        out = run_git(
            ["git", "rev-list", "--reverse", "--no-abbrev-commit", rev_spec],
            cwd=repo_path,
        )
        return [c for c in out.splitlines() if len(c) == 40] if out else []
    except Exception:
        return []


def process_patch_id_chunk(args: tuple[str, list[str]]) -> list[tuple[str, str]]:
    """Worker function: Computes patch IDs for a chunk of SHAs on a single CPU core."""
    repo_path, shas = args
    input_shas = "\n".join(shas) + "\n"

    log_cmd = [
        "git",
        "--no-pager",
        "log",
        "--no-walk",
        "--stdin",
        "-p",
        "--no-renames",
        "--no-abbrev-commit",
    ]
    log_proc = subprocess.Popen(
        log_cmd,
        cwd=repo_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        errors="replace",
        bufsize=1024 * 1024,
    )

    patch_cmd = ["git", "patch-id", "--stable"]
    patch_proc = subprocess.Popen(
        patch_cmd,
        stdin=log_proc.stdout,
        stdout=subprocess.PIPE,
        text=True,
        errors="replace",
        bufsize=1024 * 1024,
    )
    log_proc.stdout.close()

    try:
        log_proc.stdin.write(input_shas)
        log_proc.stdin.close()
    except BrokenPipeError:
        pass

    results = []
    for line in patch_proc.stdout:
        parts = line.strip().split()
        if len(parts) == 2:
            patch_id, sha = parts[0], parts[1].lower()
            if len(sha) == 40:
                results.append((patch_id, sha))

    patch_proc.stdout.close()
    patch_proc.wait()
    log_proc.wait()
    return results


def stream_commit_messages(repo_path: str, rev_spec: str):
    """Streams commit hashes and message bodies using NUL-byte delimiters."""
    cmd = [
        "git",
        "--no-pager",
        "log",
        "--reverse",
        "--no-abbrev-commit",
        "--format=%H%n%B%x00",
        rev_spec,
    ]
    proc = subprocess.Popen(
        cmd, cwd=repo_path, stdout=subprocess.PIPE, bufsize=1024 * 1024
    )

    buffer = bytearray()
    while True:
        chunk = proc.stdout.read(65536)
        if not chunk:
            break
        buffer.extend(chunk)
        while b"\x00" in buffer:
            pos = buffer.index(b"\x00")
            record = buffer[:pos].decode("utf-8", errors="replace")
            del buffer[: pos + 1]
            if record:
                parts = record.split("\n", 1)
                sha = parts[0].strip().lower()
                body = parts[1] if len(parts) > 1 else ""
                if len(sha) == 40:
                    yield sha, body

    proc.stdout.close()
    proc.wait()


def process_repository(raw_repo_path: str, db_path: str, num_workers: int):
    repo_path = os.path.abspath(os.path.expanduser(raw_repo_path))

    if not os.path.exists(repo_path):
        print(f"Error: Repository path '{repo_path}' does not exist.")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    init_db(conn)

    try:
        run_git(["git", "rev-parse", "--git-dir"], cwd=repo_path)
    except subprocess.CalledProcessError:
        print(f"Error: Path '{repo_path}' is not a valid Git repository.")
        sys.exit(1)

    last_commit = get_last_processed_commit(conn, repo_path)
    if last_commit:
        rev_spec = f"{last_commit}..HEAD"
        print(f"Resuming scan from last commit checkpoint: {last_commit[:10]}...")
    else:
        rev_spec = "HEAD"
        print("Starting full scan from beginning of repository...")

    print(f"Fetching commit list for range ({rev_spec})...")
    new_commits = get_commit_list(repo_path, rev_spec)
    total_new_commits = len(new_commits)

    if total_new_commits == 0:
        print("No new commits to process.")
        conn.close()
        return

    print(
        f"Found {total_new_commits:,} new commits. Using {num_workers} CPU cores for processing."
    )

    dsu = DisjointSet()
    existing_sha_to_gid = {}
    gid_to_shas = defaultdict(list)

    # 1. Load and reconstruct existing database groups in DSU
    print("Loading existing database state into memory...")
    cur = conn.cursor()
    cur.execute("SELECT hex(hash_value), group_id FROM hashes")
    for sha_hex, gid in cur.fetchall():
        sha_lower = sha_hex.lower()
        if len(sha_lower) == 40:
            existing_sha_to_gid[sha_lower] = gid
            gid_to_shas[gid].append(sha_lower)

    for gid, shas in gid_to_shas.items():
        first_sha = shas[0]
        for other_sha in shas[1:]:
            dsu.union(first_sha, other_sha)

    # 2. Stream and match commit messages with improved live progress
    print("Scanning commit messages for explicit cherry-pick tags...")
    latest_commit = None
    msg_count = 0
    for sha, body in stream_commit_messages(repo_path, rev_spec):
        latest_commit = sha
        msg_count += 1
        dsu.find(sha)

        match = CHERRY_PICK_RE.search(body)
        if match:
            original_sha = match.group(1).lower()
            if len(original_sha) == 40:
                dsu.union(sha, original_sha)

        if msg_count % 1000 == 0:
            pct = min((msg_count / total_new_commits) * 100, 100.0)
            sys.stdout.write(
                f"\r\033[K  Message Scan: {msg_count:,}/{total_new_commits:,} commits ({pct:.1f}%)"
            )
            sys.stdout.flush()

    # Always render final line state
    pct = min((msg_count / total_new_commits) * 100, 100.0)
    sys.stdout.write(
        f"\r\033[K  Message Scan: {msg_count:,}/{total_new_commits:,} commits ({pct:.1f}%)\n"
    )
    sys.stdout.flush()

    # 3. Parallel patch-ID computation
    existing_db_shas = list(existing_sha_to_gid.keys())
    shas_to_scan = list(dict.fromkeys(new_commits + existing_db_shas))

    print(
        f"Calculating patch IDs for {len(shas_to_scan):,} total commits across {num_workers} workers..."
    )
    chunks = [
        (repo_path, shas_to_scan[i : i + CHUNK_SIZE])
        for i in range(0, len(shas_to_scan), CHUNK_SIZE)
    ]

    patch_to_shas = defaultdict(list)
    processed_patches = 0
    total_scan_count = len(shas_to_scan)

    with multiprocessing.Pool(processes=num_workers) as pool:
        for chunk_results in pool.imap_unordered(process_patch_id_chunk, chunks):
            for patch_id, sha in chunk_results:
                patch_to_shas[patch_id].append(sha)
                processed_patches += 1

            pct = min((processed_patches / total_scan_count) * 100, 100.0)
            sys.stdout.write(
                f"\r\033[K  Patch-ID Scan: {processed_patches:,}/{total_scan_count:,} patches processed ({pct:.1f}%)"
            )
            sys.stdout.flush()

    sys.stdout.write(
        f"\r\033[K  Patch-ID Scan: {processed_patches:,}/{total_scan_count:,} patches processed ({pct:.1f}%)\n"
    )
    sys.stdout.flush()

    # Group commits sharing identical patch-ids
    print("Grouping identical patches...")
    for patch_id, shas in patch_to_shas.items():
        if len(shas) > 1:
            first_sha = shas[0]
            for other_sha in shas[1:]:
                dsu.union(first_sha, other_sha)

    # 4. Resolve group IDs and bulk write to SQLite
    print("Writing groups to SQLite...")
    root_to_members = defaultdict(list)
    for sha in dsu.parent:
        root = dsu.find(sha)
        root_to_members[root].append(sha)

    max_gid = max(existing_sha_to_gid.values(), default=0)
    next_gid = max_gid + 1

    db_records = []
    for root, members in root_to_members.items():
        existing_gids = {
            existing_sha_to_gid[m] for m in members if m in existing_sha_to_gid
        }

        if len(members) < 2 and not existing_gids:
            continue

        target_gid = min(existing_gids) if existing_gids else next_gid
        if not existing_gids:
            next_gid += 1

        for sha in members:
            if len(sha) == 40:
                try:
                    b_sha = bytes.fromhex(sha)
                    if len(b_sha) == 20:
                        db_records.append((b_sha, target_gid))
                except ValueError:
                    continue

    with conn:
        conn.executemany(
            "INSERT OR REPLACE INTO hashes (hash_value, group_id) VALUES (?, ?)",
            db_records,
        )
        if latest_commit and len(latest_commit) == 40:
            conn.execute(
                "INSERT OR REPLACE INTO state (key, value) VALUES ('last_commit', ?)",
                (latest_commit,),
            )

    conn.close()
    print(f"Done! Saved {len(db_records):,} linked commit hashes to DB.")


if __name__ == "__main__":
    cpu_count = os.cpu_count() or 4

    parser = argparse.ArgumentParser(
        description="Scan a Git repository for cherry-picks and group matching commit hashes in SQLite.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "repo_path",
        nargs="?",
        help="Path to the Git repository target directory.",
    )
    parser.add_argument(
        "--db",
        default=DB_NAME,
        help="Path to the SQLite database file.",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=cpu_count,
        help="Number of parallel worker processes to spawn.",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    process_repository(args.repo_path, args.db, args.jobs)