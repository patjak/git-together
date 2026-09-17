#!/usr/bin/python3

import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

from scan import (
    CHERRY_PICK_RE,
    DisjointSet,
    get_commit_list,
    init_db,
    process_patch_id_chunk,
    process_repository,
    stream_commit_messages,
)


class TestDisjointSet(unittest.TestCase):
    """Unit tests for the DisjointSet (Union-Find) data structure."""

    def test_find_and_union(self):
        dsu = DisjointSet()
        self.assertEqual(dsu.find("a"), "a")
        self.assertEqual(dsu.find("b"), "b")

        dsu.union("a", "b")
        self.assertEqual(dsu.find("a"), dsu.find("b"))

    def test_transitive_union(self):
        dsu = DisjointSet()
        dsu.union("a", "b")
        dsu.union("b", "c")
        self.assertEqual(dsu.find("a"), dsu.find("c"))


class TestRegex(unittest.TestCase):
    """Unit tests for cherry-pick tag regex parsing."""

    def test_cherry_pick_regex(self):
        sha = "a" * 40
        msg = f"Some commit message\n\n(cherry picked from commit {sha})"
        match = CHERRY_PICK_RE.search(msg)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), sha)

    def test_invalid_cherry_pick_regex(self):
        msg = "Just a regular commit message without tag"
        self.assertIsNone(CHERRY_PICK_RE.search(msg))

        short_sha = "(cherry picked from commit abc1234)"
        self.assertIsNone(CHERRY_PICK_RE.search(short_sha))


class TestDatabaseInit(unittest.TestCase):
    """Unit tests for SQLite database initialization."""

    def test_init_db(self):
        conn = sqlite3.connect(":memory:")
        init_db(conn)

        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cur.fetchall()}
        self.assertIn("hashes", tables)
        self.assertIn("state", tables)
        conn.close()


class TestGitIntegration(unittest.TestCase):
    """Integration tests using temporary Git repositories."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.repo_path = os.path.join(self.temp_dir, "test_repo")
        self.db_path = os.path.join(self.temp_dir, "test.db")

        os.makedirs(self.repo_path)
        self._run_git(["git", "init"])
        self._run_git(["git", "config", "user.name", "Test User"])
        self._run_git(["git", "config", "user.email", "test@example.com"])

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _run_git(self, cmd: list[str]) -> str:
        res = subprocess.run(
            cmd, cwd=self.repo_path, capture_output=True, text=True, check=True
        )
        return res.stdout.strip()

    def _make_commit(self, file_name: str, content: str, msg: str) -> str:
        file_path = os.path.join(self.repo_path, file_name)
        with open(file_path, "a") as f:
            f.write(content)
        self._run_git(["git", "add", file_name])
        self._run_git(["git", "commit", "-m", msg])
        return self._run_git(["git", "rev-parse", "HEAD"])

    def test_commit_streaming_and_list(self):
        sha1 = self._make_commit("file.txt", "line 1\n", "Initial commit")
        sha2 = self._make_commit("file.txt", "line 2\n", "Second commit")

        commit_list = get_commit_list(self.repo_path, "HEAD")
        self.assertEqual(commit_list, [sha1, sha2])

        messages = list(stream_commit_messages(self.repo_path, "HEAD"))
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0][0], sha1)
        self.assertIn("Initial commit", messages[0][1])

    def test_process_patch_id_chunk(self):
        sha1 = self._make_commit("file.txt", "line 1\n", "Feature patch")
        results = process_patch_id_chunk((self.repo_path, [sha1]))

        self.assertEqual(len(results), 1)
        patch_id, subject, returned_sha = results[0]
        self.assertEqual(returned_sha, sha1)
        self.assertEqual(subject, "Feature patch")
        self.assertTrue(len(patch_id) > 0)

    def test_revert_of_revert_not_grouped(self):
        """Verifies that a revert of a revert is NOT grouped despite having an identical diff."""
        sha1 = self._make_commit("file.txt", "feature content\n", "Add feature")

        # Revert the feature
        self._run_git(["git", "revert", "--no-edit", sha1])

        # Revert the revert (restores feature content with identical diff, but different subject)
        sha3 = self._run_git(["git", "revert", "--no-edit", "HEAD"])

        process_repository(self.repo_path, self.db_path, num_workers=2)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT hex(hash_value), group_id FROM hashes")
        records = cur.fetchall()
        conn.close()

        # Check if sha1 and sha3 are in the same group
        sha_to_group = {sha.lower(): gid for sha, gid in records}

        if sha1.lower() in sha_to_group and sha3.lower() in sha_to_group:
            self.assertNotEqual(
                sha_to_group[sha1.lower()],
                sha_to_group[sha3.lower()],
                "Revert of revert should NOT share a group ID with original commit",
            )

    def test_cherry_pick_grouped(self):
        """Verifies that an explicit cherry-pick (-x) IS correctly grouped."""
        base_sha = self._make_commit("base.txt", "base\n", "Base commit")
        sha1 = self._make_commit("file.txt", "cherry content\n", "Cherry candidate")

        # Create topic branch off base commit and cherry-pick
        self._run_git(["git", "checkout", "-b", "topic", base_sha])
        self._run_git(["git", "cherry-pick", "-x", sha1])
        sha2 = self._run_git(["git", "rev-parse", "HEAD"])

        process_repository(self.repo_path, self.db_path, num_workers=2)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT hex(hash_value), group_id FROM hashes")
        records = cur.fetchall()
        conn.close()

        sha_to_group = {sha.lower(): gid for sha, gid in records}
        self.assertIn(sha1.lower(), sha_to_group)
        self.assertIn(sha2.lower(), sha_to_group)
        self.assertEqual(
            sha_to_group[sha1.lower()],
            sha_to_group[sha2.lower()],
            "Cherry-picked commits should share the same group ID",
        )


if __name__ == "__main__":
    unittest.main()

