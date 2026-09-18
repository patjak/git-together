#!/usr/bin/python3

import argparse
import multiprocessing
import os
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict
from enum import IntEnum
from typing import List, Optional, Set, Tuple

try:
    from rapidfuzz import fuzz

    HAS_RAPIDFUZZ = True
except ImportError:
    import difflib

    HAS_RAPIDFUZZ = False

DB_NAME = "git-together.db"
CHERRY_PICK_RE = re.compile(r"\(cherry picked from commit ([a-fA-F0-9]{40})\)")
CHUNK_SIZE = 2000  # Number of commits per worker task
BUCKET_CHUNK_SIZE = 20  # Reduced chunk size for granular worker load-balancing
MAX_FUZZY_BUCKET_SIZE = 50  # Cap O(N^2) fuzzy matching on generic subject buckets
TRAILER_LINE_RE = re.compile(
    r"^[A-Za-z0-9-]+:\s+.*$|^[A-Za-z0-9-]+\s+#\d+.*$", re.IGNORECASE
)


class DetectionType(IntEnum):
    CHERRY_PICK = 1
    PATCH_ID_SUBJECT = 2
    SUBJECT_CLEAN_BODY = 3
    SUBJECT_FUZZY_BODY = 4


def strip_trailers_and_normalize(body: str) -> str:
    lines = body.strip().splitlines()

    # Walk backward from the end to remove the bottom trailer block
    idx = len(lines) - 1
    while idx >= 0:
        line = lines[idx].strip()
        if not line:
            idx -= 1
            continue
        if TRAILER_LINE_RE.match(line):
            idx -= 1
        else:
            break

    cleaned_lines = lines[: idx + 1]
    return " ".join(" ".join(cleaned_lines).lower().split())


def compute_similarity(s1: str, s2: str) -> float:
    """Calculates string similarity using rapidfuzz (if available) or difflib fallback."""
    if HAS_RAPIDFUZZ:
        return fuzz.ratio(s1, s2) / 100.0
    return difflib.SequenceMatcher(None, s1, s2).ratio()


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


def run_git(cmd: List[str], cwd: str = ".") -> str:
    res = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        errors="replace",
        check=True,
    )
    return res.stdout.strip()


def init_db(conn: sqlite3.Connection):
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hashes (
                hash_value BLOB NOT NULL PRIMARY KEY CHECK(length(hash_value) = 20),
                group_id INTEGER NOT NULL,
                detection_type INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_hashes_group ON hashes(group_id);

            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)


def get_last_processed_commit(conn: sqlite3.Connection, repo_path: str) -> Optional[str]:
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


def get_commit_list(repo_path: str, rev_spec: str) -> List[str]:
    """Returns an ordered list of full 40-character commit SHAs."""
    try:
        out = run_git(
            ["git", "rev-list", "--reverse", "--no-abbrev-commit", rev_spec],
            cwd=repo_path,
        )
        return [c for c in out.splitlines() if len(c) == 40] if out else []
    except Exception:
        return []


def process_patch_id_chunk(args: Tuple[str, List[str]]) -> Tuple[List[Tuple[str, str]], dict]:
    """Worker function: Computes patch IDs, subjects, and cleaned bodies for a chunk of SHAs."""
    repo_path, shas = args
    input_shas = "\n".join(shas) + "\n"

    log_cmd = [
        "git",
        "--no-pager",
        "log",
        "--ignore-missing",
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
        universal_newlines=True,
        errors="replace",
        bufsize=1024 * 1024,
    )

    patch_cmd = ["git", "patch-id", "--stable"]
    patch_proc = subprocess.Popen(
        patch_cmd,
        stdin=log_proc.stdout,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        errors="replace",
        bufsize=1024 * 1024,
    )
    log_proc.stdout.close()

    try:
        log_proc.stdin.write(input_shas)
        log_proc.stdin.close()
    except BrokenPipeError:
        pass

    raw_patch_results = []
    for line in patch_proc.stdout:
        parts = line.strip().split()
        if len(parts) == 2:
            patch_id, sha = parts[0], parts[1].lower()
            if len(sha) == 40:
                raw_patch_results.append((patch_id, sha))

    patch_proc.stdout.close()
    patch_proc.wait()
    log_proc.wait()

    # Retrieve subject lines and commit bodies using NUL-delimited binary format
    sha_to_info = {}
    subject_cmd = [
        "git",
        "--no-pager",
        "log",
        "-z",
        "--ignore-missing",
        "--no-walk",
        "--stdin",
        "--format=%H%n%s%n%b",
    ]
    subj_proc = subprocess.Popen(
        subject_cmd,
        cwd=repo_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=1024 * 1024,
    )
    try:
        subj_proc.stdin.write(input_shas.encode("utf-8"))
        subj_proc.stdin.close()
    except BrokenPipeError:
        pass

    buffer = bytearray()
    while True:
        chunk = subj_proc.stdout.read(65536)
        if not chunk:
            break
        buffer.extend(chunk)
        while b"\x00" in buffer:
            pos = buffer.index(b"\x00")
            record = buffer[:pos].decode("utf-8", errors="replace")
            del buffer[: pos + 1]
            if record:
                parts = record.split("\n", 2)
                if len(parts) >= 1 and len(parts[0].strip()) == 40:
                    sha = parts[0].strip().lower()
                    subject = parts[1].strip() if len(parts) > 1 else ""
                    body = parts[2] if len(parts) > 2 else ""
                    cleaned_body = strip_trailers_and_normalize(body)
                    sha_to_info[sha] = (subject, cleaned_body)

    subj_proc.stdout.close()
    subj_proc.wait()

    return raw_patch_results, sha_to_info


def process_subject_bucket_chunk(
    chunk_buckets: List[List[Tuple[str, str]]]
) -> Tuple[int, List[List[str]], List[Tuple[str, str]]]:
    """Worker function: Evaluates subject buckets in parallel for clean and fuzzy body matches."""
    clean_matches = []
    fuzzy_matches = []

    for sha_tuples in chunk_buckets:
        body_to_shas = defaultdict(list)
        for sha, cb in sha_tuples:
            if cb:
                body_to_shas[cb].append(sha)

        matched_in_subject = set()
        for cb, group_shas in body_to_shas.items():
            if len(group_shas) > 1:
                clean_matches.append(group_shas)
                matched_in_subject.update(group_shas)

        unmatched = [
            (sha, cb) for sha, cb in sha_tuples if sha not in matched_in_subject and cb
        ]

        # Cap O(N^2) fuzzy matching pass on generic subjects with large numbers of distinct bodies
        if 1 < len(unmatched) <= MAX_FUZZY_BUCKET_SIZE:
            for i in range(len(unmatched)):
                sha1, cb1 = unmatched[i]
                for j in range(i + 1, len(unmatched)):
                    sha2, cb2 = unmatched[j]
                    len1, len2 = len(cb1), len(cb2)
                    if min(len1, len2) / max(len1, len2) < 0.70:
                        continue
                    if compute_similarity(cb1, cb2) >= 0.85:
                        fuzzy_matches.append((sha1, sha2))

    return len(chunk_buckets), clean_matches, fuzzy_matches


def stream_commit_messages(repo_path: str, rev_spec: str):
    """Streams commit hashes and message bodies using binary-safe NUL (-z) delimiters."""
    cmd = [
        "git",
        "--no-pager",
        "log",
        "-z",
        "--reverse",
        "--no-abbrev-commit",
        "--format=%H%n%B",
        rev_spec,
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=repo_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1024 * 1024,
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
    stderr_err = proc.stderr.read().decode("utf-8", errors="replace")
    proc.stderr.close()
    proc.wait()

    if proc.returncode != 0 and stderr_err.strip():
        print(f"\nWarning: git log process returned error:\n{stderr_err.strip()}", file=sys.stderr)


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
    new_commits_set = set(new_commits)

    if total_new_commits == 0:
        print("No new commits to process.")
        conn.close()
        return

    print(
        f"Found {total_new_commits:,} new commits. Using {num_workers} CPU cores for processing."
    )
    if HAS_RAPIDFUZZ:
        print("Using rapidfuzz (C++ engine) for high-performance fuzzy body matching.")
    else:
        print("Using difflib fallback for fuzzy body matching (install 'rapidfuzz' for faster scans).")

    dsu = DisjointSet()
    existing_sha_to_gid = {}
    gid_to_shas = defaultdict(list)
    sha_detection = defaultdict(set)

    # 1. Load and reconstruct existing database groups in DSU
    print("Loading existing database state into memory...")
    cur = conn.cursor()
    cur.execute("SELECT hex(hash_value), group_id, detection_type FROM hashes")
    for sha_hex, gid, dt_int in cur.fetchall():
        sha_lower = sha_hex.lower()
        if len(sha_lower) == 40:
            existing_sha_to_gid[sha_lower] = gid
            gid_to_shas[gid].append(sha_lower)
            if dt_int is not None:
                try:
                    sha_detection[sha_lower].add(DetectionType(dt_int))
                except ValueError:
                    pass

    for gid, shas in gid_to_shas.items():
        first_sha = shas[0]
        for other_sha in shas[1:]:
            dsu.union(first_sha, other_sha)

    # 2. Stream and match commit messages for explicit tags
    print("Scanning commit messages for explicit cherry-pick tags...")
    latest_commit = None
    msg_count = 0
    tag_match_count = 0

    for sha, body in stream_commit_messages(repo_path, rev_spec):
        latest_commit = sha
        msg_count += 1
        dsu.find(sha)

        match = CHERRY_PICK_RE.search(body)
        if match:
            original_sha = match.group(1).lower()
            if len(original_sha) == 40:
                dsu.union(sha, original_sha)
                tag_match_count += 1
                sha_detection[sha].add(DetectionType.CHERRY_PICK)
                sha_detection[original_sha].add(DetectionType.CHERRY_PICK)

        if msg_count % 1000 == 0:
            pct = min((msg_count / total_new_commits) * 100, 100.0)
            sys.stdout.write(
                f"\r\033[K  Message Scan: {msg_count:,}/{total_new_commits:,} commits ({pct:.1f}%)"
            )
            sys.stdout.flush()

    pct = min((msg_count / total_new_commits) * 100, 100.0)
    sys.stdout.write(
        f"\r\033[K  Message Scan: {msg_count:,}/{total_new_commits:,} commits ({pct:.1f}%)\n"
    )
    sys.stdout.flush()
    print(f"  -> Detected {tag_match_count:,} new commits via explicit 'cherry picked from' tags.")

    # 3. Parallel patch-ID, subject, and cleaned body extraction
    existing_db_shas = list(existing_sha_to_gid.keys())
    shas_to_scan = list(dict.fromkeys(new_commits + existing_db_shas))

    print(
        f"Calculating patch IDs, subjects, and cleaned bodies for {len(shas_to_scan):,} commits across {num_workers} workers..."
    )
    chunks = [
        (repo_path, shas_to_scan[i : i + CHUNK_SIZE])
        for i in range(0, len(shas_to_scan), CHUNK_SIZE)
    ]

    patch_to_shas = defaultdict(list)
    sha_to_subject = {}
    sha_to_cleaned_body = {}
    processed_patches = 0
    total_scan_count = len(shas_to_scan)

    with multiprocessing.Pool(processes=num_workers) as pool:
        for raw_patch_results, sha_to_info in pool.imap_unordered(
            process_patch_id_chunk, chunks
        ):
            for patch_id, sha in raw_patch_results:
                subj = sha_to_info.get(sha, ("", ""))[0]
                patch_to_shas[(patch_id, subj)].append(sha)
                processed_patches += 1

            for sha, (subj, cb) in sha_to_info.items():
                if subj:
                    sha_to_subject[sha] = subj
                    sha_to_cleaned_body[sha] = cb

            pct = min((processed_patches / total_scan_count) * 100, 100.0)
            sys.stdout.write(
                f"\r\033[K  Patch-ID & Body Scan: {processed_patches:,}/{total_scan_count:,} patches processed ({pct:.1f}%)"
            )
            sys.stdout.flush()

    sys.stdout.write(
        f"\r\033[K  Patch-ID & Body Scan: {processed_patches:,}/{total_scan_count:,} patches processed ({pct:.1f}%)\n"
    )
    sys.stdout.flush()

    # Pass 1: Group commits sharing identical patch-ids and commit subjects
    print("Grouping identical patches with matching subjects...")
    patch_group_count = 0
    patch_commit_count = 0

    for (patch_id, subject), shas in patch_to_shas.items():
        if len(shas) > 1:
            first_sha = shas[0]
            for other_sha in shas[1:]:
                dsu.union(first_sha, other_sha)

            for s in shas:
                sha_detection[s].add(DetectionType.PATCH_ID_SUBJECT)

            new_in_group = [s for s in shas if s in new_commits_set]
            if new_in_group:
                patch_group_count += 1
                patch_commit_count += len(new_in_group)

    # Pass 2 & 3: Parallel evaluation of subject buckets for Clean Body & Fuzzy Body matching
    subject_to_shas = defaultdict(list)
    for sha, subj in sha_to_subject.items():
        if subj:
            subject_to_shas[subj].append(sha)

    candidate_buckets = [
        [(s, sha_to_cleaned_body.get(s, "")) for s in shas]
        for shas in subject_to_shas.values()
        if len(shas) >= 2
    ]

    # Sort candidate buckets by size descending (Longest Processing Time First)
    candidate_buckets.sort(key=len, reverse=True)

    clean_body_group_count = 0
    clean_body_commit_count = 0
    fuzzy_body_group_count = 0
    fuzzy_body_commit_count = 0

    if candidate_buckets:
        print(
            f"Evaluating {len(candidate_buckets):,} subject buckets across {num_workers} workers (sorted heaviest first)..."
        )
        bucket_chunks = [
            candidate_buckets[i : i + BUCKET_CHUNK_SIZE]
            for i in range(0, len(candidate_buckets), BUCKET_CHUNK_SIZE)
        ]

        processed_buckets = 0
        total_buckets = len(candidate_buckets)

        with multiprocessing.Pool(processes=num_workers) as pool:
            for count, clean_matches, fuzzy_matches in pool.imap_unordered(
                process_subject_bucket_chunk, bucket_chunks
            ):
                processed_buckets += count

                for group_shas in clean_matches:
                    first_sha = group_shas[0]
                    for other_sha in group_shas[1:]:
                        dsu.union(first_sha, other_sha)

                    for s in group_shas:
                        sha_detection[s].add(DetectionType.SUBJECT_CLEAN_BODY)

                    new_in_group = [s for s in group_shas if s in new_commits_set]
                    if new_in_group:
                        clean_body_group_count += 1
                        clean_body_commit_count += len(new_in_group)

                for sha1, sha2 in fuzzy_matches:
                    dsu.union(sha1, sha2)
                    sha_detection[sha1].add(DetectionType.SUBJECT_FUZZY_BODY)
                    sha_detection[sha2].add(DetectionType.SUBJECT_FUZZY_BODY)

                    if sha1 in new_commits_set or sha2 in new_commits_set:
                        fuzzy_body_group_count += 1
                        if sha1 in new_commits_set:
                            fuzzy_body_commit_count += 1
                        if sha2 in new_commits_set:
                            fuzzy_body_commit_count += 1

                pct = min((processed_buckets / total_buckets) * 100, 100.0)
                sys.stdout.write(
                    f"\r\033[K  Subject Bucket Scan: {processed_buckets:,}/{total_buckets:,} buckets evaluated ({pct:.1f}%)"
                )
                sys.stdout.flush()

        sys.stdout.write(
            f"\r\033[K  Subject Bucket Scan: {processed_buckets:,}/{total_buckets:,} buckets evaluated ({pct:.1f}%)\n"
        )
        sys.stdout.flush()

    print("\n--- Detection Summary (Current Run Only) ---")
    print(f"  Explicit Tags Found     : {tag_match_count:,} commits")
    print(f"  Patch-ID+Subject Match  : {patch_commit_count:,} commits ({patch_group_count:,} groups)")
    print(f"  Subject+Clean Body Match: {clean_body_commit_count:,} commits ({clean_body_group_count:,} groups)")
    print(f"  Subject+Fuzzy Body Match: {fuzzy_body_commit_count:,} commits ({fuzzy_body_group_count:,} groups)")
    print("--------------------------------------------\n")

    # 4. Resolve group IDs and bulk write to SQLite with prioritized detection types
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
                        types = sha_detection.get(sha, set())
                        if DetectionType.CHERRY_PICK in types:
                            dt_val = DetectionType.CHERRY_PICK
                        elif DetectionType.PATCH_ID_SUBJECT in types:
                            dt_val = DetectionType.PATCH_ID_SUBJECT
                        elif DetectionType.SUBJECT_CLEAN_BODY in types:
                            dt_val = DetectionType.SUBJECT_CLEAN_BODY
                        elif DetectionType.SUBJECT_FUZZY_BODY in types:
                            dt_val = DetectionType.SUBJECT_FUZZY_BODY
                        else:
                            dt_val = DetectionType.CHERRY_PICK

                        db_records.append((b_sha, target_gid, dt_val.value))
                except ValueError:
                    continue

    with conn:
        conn.executemany(
            "INSERT OR REPLACE INTO hashes (hash_value, group_id, detection_type) VALUES (?, ?, ?)",
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