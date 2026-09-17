#!/usr/bin/python3

import argparse
import os
import re
import sqlite3
import sys
from pathlib import Path

DB_NAME = "git-together.db"

GIT_COMMIT_RE = re.compile(
    r"^\s*Git-commit:\s*[\[<]?\s*([a-fA-F0-9]{40})\s*[\]>]?",
    re.IGNORECASE | re.MULTILINE,
)
ALT_COMMIT_RE = re.compile(
    r"^\s*Alt-commit:\s*[\[<]?\s*([a-fA-F0-9]{40})\s*[\]>]?",
    re.IGNORECASE | re.MULTILINE,
)


def extract_commit_hashes(file_path: Path) -> tuple[list[str], list[str]]:
    """Extracts Git-commit and Alt-commit hashes from a patch file."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        git_shas = [m.lower() for m in GIT_COMMIT_RE.findall(content)]
        alt_shas = [m.lower() for m in ALT_COMMIT_RE.findall(content)]
        return git_shas, alt_shas
    except Exception as e:
        print(f"Warning: Could not read '{file_path}': {e}", file=sys.stderr)
        return [], []


def batch_get_sha_groups(
    conn: sqlite3.Connection, shas: set[str]
) -> dict[str, int]:
    """Queries SQLite for a set of SHAs and returns a mapping of SHA -> group_id."""
    if not shas:
        return {}

    sha_to_group = {}
    sha_list = list(shas)
    chunk_size = 900  # SQLite variable limit for IN clauses

    cur = conn.cursor()
    for i in range(0, len(sha_list), chunk_size):
        chunk = sha_list[i : i + chunk_size]
        blob_params = []

        for sha in chunk:
            try:
                blob_params.append(bytes.fromhex(sha))
            except ValueError:
                continue

        if not blob_params:
            continue

        placeholders = ",".join(["?"] * len(blob_params))
        query = f"SELECT hex(hash_value), group_id FROM hashes WHERE hash_value IN ({placeholders})"

        cur.execute(query, blob_params)
        for hex_val, group_id in cur.fetchall():
            sha_to_group[hex_val.lower()] = group_id

    return sha_to_group


def verify_patch_directory(dir_path: Path, db_path: str, recursive: bool):
    if not dir_path.is_dir():
        print(f"Error: Path '{dir_path}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(db_path):
        print(f"Error: Database file '{db_path}' not found.", file=sys.stderr)
        sys.exit(1)

    pattern = "**/*.patch" if recursive else "*.patch"
    patch_files = list(dir_path.glob(pattern))

    if not patch_files:
        print(f"No .patch files found in '{dir_path}'.")
        return

    # 1. Filter files, keeping ONLY those with an Alt-commit tag
    file_to_shas = {}
    all_shas = set()

    for pf in patch_files:
        git_shas, alt_shas = extract_commit_hashes(pf)

        # Skip files that don't have an Alt-commit tag
        if not alt_shas:
            continue

        combined_shas = list(dict.fromkeys(git_shas + alt_shas))
        file_to_shas[pf] = combined_shas
        all_shas.update(combined_shas)

    if not file_to_shas:
        print(f"Scanned {len(patch_files):,} .patch files, but none contained an Alt-commit tag.")
        return

    # 2. Query database for collected SHAs
    conn = sqlite3.connect(db_path)
    sha_to_group = batch_get_sha_groups(conn, all_shas)
    conn.close()

    # 3. Check compliance
    compliant_files = []
    non_compliant_files = []

    for pf, shas in file_to_shas.items():
        missing_shas = [sha for sha in shas if sha not in sha_to_group]
        if missing_shas:
            reason = f"Missing from DB: {', '.join(missing_shas[:3])}" + (
                f" (+{len(missing_shas) - 3} more)" if len(missing_shas) > 3 else ""
            )
            non_compliant_files.append((pf, reason))
            continue

        group_ids = {sha_to_group[sha] for sha in shas}
        if len(group_ids) > 1:
            group_details = ", ".join(
                f"{sha[:10]}->GID:{sha_to_group[sha]}" for sha in shas
            )
            reason = f"Split across multiple groups ({group_details})"
            non_compliant_files.append((pf, reason))
        else:
            compliant_files.append(pf)

    # 4. Print simplified stats report
    print("\n" + "=" * 50)
    print("        ALT-COMMIT GROUP COMPLIANCE REPORT        ")
    print("=" * 50)
    print(f"Total .patch files scanned : {len(patch_files):,}")
    print(f"Files with Alt-commit tag  : {len(file_to_shas):,}")
    print(f"Compliant files            : {len(compliant_files):,}")
    print(f"Non-compliant files        : {len(non_compliant_files):,}")
    print("=" * 50 + "\n")

    if non_compliant_files:
        print("NON-COMPLIANT PATCH FILES:")
        print("-" * 50)
        for pf, reason in non_compliant_files:
            rel_path = pf.relative_to(dir_path) if pf.is_relative_to(dir_path) else pf
            print(f"  [FAIL] {rel_path}")
            print(f"         Reason: {reason}")
        print("-" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify that patch files containing Alt-commit tags belong to the same database group as Git-commit tags.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "directory",
        type=Path,
        help="Path to directory containing .patch files.",
    )
    parser.add_argument(
        "--db",
        default=DB_NAME,
        help="Path to the SQLite database file.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories for .patch files.",
    )

    args = parser.parse_args()
    verify_patch_directory(args.directory, args.db, args.recursive)

