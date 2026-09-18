#!/usr/bin/python3

import argparse
import os
import sqlite3
import sys

DB_NAME = "git-together.db"

DETECTION_LABELS = {
    1: "Explicit Cherry-Pick Tag",
    2: "Subject + Clean Body Match",
    3: "Subject + Fuzzy Body Match",
    4: "Patch-ID + Subject Fallback",
    5: "Subject + Author Date Match",
}

EXAMPLES_TEXT = """examples:
  python3 lookup.py e4e9b9248ff       # Lookup sibling hashes for a commit SHA
  python3 lookup.py e4e9b9248ff 1042a  # Compare two SHAs (exits with code 0 on match, 1 otherwise)
  python3 lookup.py 1042              # Lookup all hashes in Group #1042
  python3 lookup.py stats             # Show database statistics
  python3 lookup.py --db custom.db 22 # Query against a custom SQLite DB file
"""


def format_size(size_bytes: int) -> str:
    """Formats file size into human-readable units."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def resolve_sha_group(db_path: str, query_hash: str) -> int:
    """Resolves a full or short SHA to its group_id."""
    if not os.path.exists(db_path):
        sys.stderr.write(f"Error: Database file '{db_path}' not found.\n")
        sys.exit(1)

    clean_hash = query_hash.strip().lower()

    if not all(c in "0123456789abcdef" for c in clean_hash):
        sys.stderr.write(f"Error: '{query_hash}' is not a valid hexadecimal commit SHA.\n")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Support prefix resolution for short SHAs
    if len(clean_hash) < 40:
        cur.execute(
            "SELECT hex(hash_value) FROM hashes WHERE hex(hash_value) LIKE ?",
            (clean_hash.upper() + "%",),
        )
        matches = [r[0].lower() for r in cur.fetchall()]

        if not matches:
            sys.stderr.write(f"Error: No commits matching prefix '{clean_hash}' found.\n")
            conn.close()
            sys.exit(1)
        elif len(matches) > 1:
            sys.stderr.write(f"Error: Ambiguous prefix '{clean_hash}' matches {len(matches)} commits.\n")
            conn.close()
            sys.exit(1)
        else:
            clean_hash = matches[0]

    target_blob = bytes.fromhex(clean_hash)
    cur.execute("SELECT group_id FROM hashes WHERE hash_value = ?", (target_blob,))
    row = cur.fetchone()
    conn.close()

    if not row:
        sys.stderr.write(f"Error: Commit SHA '{clean_hash}' not found in database.\n")
        sys.exit(1)

    return row[0]


def compare_shas(db_path: str, sha1: str, sha2: str):
    """Checks if two SHAs belong to the same group and exits with 0 on match or 1 on mismatch."""
    group1 = resolve_sha_group(db_path, sha1)
    group2 = resolve_sha_group(db_path, sha2)

    if group1 == group2:
        sys.exit(0)
    else:
        sys.exit(1)


def lookup_group(db_path: str, group_id: int):
    """Prints all commit hashes belonging to a specific group_id (one per line)."""
    if not os.path.exists(db_path):
        sys.stderr.write(f"Error: Database file '{db_path}' not found.\n")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute(
        "SELECT hex(hash_value) FROM hashes WHERE group_id = ?", (group_id,)
    )
    rows = cur.fetchall()
    conn.close()

    for r in rows:
        sys.stdout.write(f"{r[0].lower()}\n")


def lookup_hash(db_path: str, query_hash: str):
    """Prints all sibling hashes sharing a group with target SHA (excluding target SHA)."""
    group_id = resolve_sha_group(db_path, query_hash)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    clean_hash = query_hash.strip().lower()
    cur.execute(
        """
        SELECT hex(hash_value)
        FROM hashes
        WHERE group_id = ? AND hex(hash_value) NOT LIKE ?
        """,
        (group_id, clean_hash + "%"),
    )
    results = cur.fetchall()
    conn.close()

    for r in results:
        sys.stdout.write(f"{r[0].lower()}\n")


def smart_lookup(db_path: str, target: str):
    """Automatically detects whether target is a Group ID or commit SHA."""
    clean = target.strip().lstrip("#").lower()

    # Explicit group format (e.g., 'g1042')
    if clean.startswith("g") and clean[1:].isdigit():
        lookup_group(db_path, int(clean[1:]))
        return

    # Pure numeric input (e.g., '1042' or '22')
    if clean.isdigit():
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM hashes WHERE group_id = ? LIMIT 1", (int(clean),))
        group_exists = cur.fetchone() is not None
        conn.close()

        if group_exists:
            lookup_group(db_path, int(clean))
            return

    # Fallback to SHA lookup
    lookup_hash(db_path, clean)


def show_stats(db_path: str):
    """Displays key statistics, detection breakdowns, and metrics for the SQLite database."""
    if not os.path.exists(db_path):
        sys.stderr.write(f"Error: Database file '{db_path}' not found.\n")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM hashes")
    total_hashes = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT group_id) FROM hashes")
    total_groups = cur.fetchone()[0]

    # Detection type breakdown query
    cur.execute("SELECT detection_type, COUNT(*) FROM hashes GROUP BY detection_type")
    type_counts = dict(cur.fetchall())

    min_sz, max_sz, avg_sz = (0, 0, 0.0)
    top_groups = []

    if total_groups > 0:
        cur.execute("""
            WITH group_sizes AS (
                SELECT COUNT(*) AS sz FROM hashes GROUP BY group_id
            )
            SELECT MIN(sz), MAX(sz), AVG(sz) FROM group_sizes
        """)
        min_sz, max_sz, avg_sz = cur.fetchone()

        cur.execute("""
            SELECT group_id, COUNT(*) as cnt
            FROM hashes
            GROUP BY group_id
            ORDER BY cnt DESC
            LIMIT 5
        """)
        top_groups = cur.fetchall()

    cur.execute("SELECT value FROM state WHERE key = 'last_commit'")
    row = cur.fetchone()
    last_commit = row[0] if row else "None"

    db_size = os.path.getsize(db_path)
    conn.close()

    print("=============================================")
    print("        DATABASE METRICS & STATISTICS        ")
    print("=============================================")
    print(f"Database Path:        {os.path.abspath(db_path)}")
    print(f"File Size:            {format_size(db_size)}")
    print(f"Last Checkpoint SHA:  {last_commit}")
    print("---------------------------------------------")
    print(f"Total Linked Hashes:  {total_hashes:,}")
    print(f"Total Unique Groups:  {total_groups:,}")
    print("---------------------------------------------")
    print("Detection Type Breakdown:")

    if total_hashes > 0:
        for dt_code, label in DETECTION_LABELS.items():
            cnt = type_counts.get(dt_code, 0)
            pct = (cnt / total_hashes) * 100.0
            print(f"  - {label:<27}: {cnt:>8,} ({pct:5.1f}%)")

        # Display any unknown/unmapped detection type codes if present
        for dt_code, cnt in type_counts.items():
            if dt_code not in DETECTION_LABELS:
                pct = (cnt / total_hashes) * 100.0
                print(f"  - Unknown Type #{dt_code:<15}: {cnt:>8,} ({pct:5.1f}%)")
    else:
        print("  (No entry records in database)")

    if total_groups > 0:
        print("---------------------------------------------")
        print(f"Min Group Size:       {min_sz}")
        print(f"Max Group Size:       {max_sz}")
        print(f"Avg Group Size:       {avg_sz:.2f} hashes/group")
        print("---------------------------------------------")
        print("Top 5 Largest Commit Groups:")
        for gid, count in top_groups:
            print(f"  - Group #{gid}: {count} commits")
    print("=============================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Query cherry-pick commit groups from SQLite.",
        epilog=EXAMPLES_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Commit SHA(s), Group ID (e.g. 1042 or g1042), or 'stats'. Pass two SHAs to compare.",
    )
    parser.add_argument(
        "--db",
        default=DB_NAME,
        help="Path to the SQLite database file.",
    )
    parser.add_argument(
        "-g",
        "--group",
        type=int,
        help="Lookup all hashes for a specific Group ID directly.",
    )

    args = parser.parse_args()

    if args.group is not None:
        lookup_group(args.db, args.group)
    elif len(args.targets) == 2:
        compare_shas(args.db, args.targets[0], args.targets[1])
    elif len(args.targets) == 1:
        if args.targets[0] == "stats":
            show_stats(args.db)
        else:
            smart_lookup(args.db, args.targets[0])
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)