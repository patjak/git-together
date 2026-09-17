# Git Cherry-Pick Hash Tracker

This repository contains a suite of tools designed to scan Git repositories, identify cherry-picked commits (both explicit and implicit), group them together, and verify SUSE patch files against these groups. All data is stored and queried using a local SQLite database.

## Quick Start & Usage Examples

### Step 1: Scan a Repository
Initialize the database by scanning a local Git repository.

```bash
# Scan a repository using all available CPU cores (creates git_hashes.db by default)
python3 scan.py /path/to/my/linux/repo

# Scan using a specific number of workers and a custom database file
python3 scan.py /path/to/my/linux/repo --db custom.db -j 8
```

### Step 2: Query the Database
Look up related commits or view database statistics.

```bash
# Show database statistics
python3 lookup.py stats

# Lookup sibling hashes for a specific commit SHA
python3 lookup.py e4e9b9248ff

# Lookup all hashes in Group #1042 (mainly used for debugging the database)
python3 lookup.py 1042
```

### Step 3: Verify Patch Files
Ensure your SUSE patches are compliant and their alt commits match known groups.

```bash
# Scan a directory of patches
python3 verify_patches.py /path/to/patches

# Scan recursively with a custom database
python3 verify_patches.py /path/to/patches --recursive --db custom.db
```

### Step 4: Run Tests
Run unit tests.

```bash
python3 tests.py
```
