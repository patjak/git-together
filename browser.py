#!/usr/bin/python3

import argparse
import os
import sqlite3
import subprocess
import sys

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen
from textual.widgets import Footer, Header, Input, Label, OptionList, Static
from textual.widgets.option_list import Option

DETECTION_NAMES = {
    1: "CHERRY_PICK_TAG",
    2: "SUBJECT_AND_TIMESTAMP",
    3: "SUBJECT_AND_MESSAGE",
    4: "SUBJECT_AND_FUZZY_MESSAGE",
    5: "PATCH_DIFF_MATCH",
}

CANCEL = object()


class FilterModal(ModalScreen):
    BINDINGS = [("escape", "cancel", "Cancel")]

    CSS = """
    FilterModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.6);
    }

    #filter-dialog {
        width: 45;
        height: 14;
        border: heavy $accent;
        background: $panel;
    }

    #filter-title {
        background: $accent;
        color: $text;
        text-align: center;
        text-style: bold;
        width: 100%;
        padding: 0 1;
    }

    FilterModal OptionList {
        height: 100%;
        border: none;
    }
    """

    def __init__(self, current_selection: int | None = None):
        super().__init__()
        self.current_selection = current_selection

    def compose(self) -> ComposeResult:
        with Vertical(id="filter-dialog"):
            yield Label("Filter by Detection Type", id="filter-title")
            yield OptionList(id="filter-options")

    def on_mount(self) -> None:
        option_list = self.query_one("#filter-options", OptionList)
        option_list.add_option(Option("All Detection Types", id="all"))

        highlight_idx = 0
        idx = 1
        for dt_id, dt_name in DETECTION_NAMES.items():
            option_list.add_option(Option(dt_name, id=str(dt_id)))
            if dt_id == self.current_selection:
                highlight_idx = idx
            idx += 1

        option_list.highlighted = highlight_idx
        option_list.focus()

    def action_cancel(self) -> None:
        self.dismiss(CANCEL)

    @on(OptionList.OptionSelected, "#filter-options")
    def on_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id == "all":
            self.dismiss(None)
        else:
            self.dismiss(int(event.option.id))


class SearchModal(ModalScreen):
    BINDINGS = [("escape", "cancel", "Cancel")]

    CSS = """
    SearchModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.6);
    }

    #search-dialog {
        width: 50;
        height: 9;
        border: heavy $accent;
        background: $panel;
    }

    #search-title {
        background: $accent;
        color: $text;
        text-align: center;
        text-style: bold;
        width: 100%;
        padding: 0 1;
    }

    #search-input {
        margin: 1 2;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="search-dialog"):
            yield Label("Search Commit Hash", id="search-title")
            yield Input(placeholder="Enter SHA (full or partial)...", id="search-input")

    def on_mount(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(CANCEL)

    @on(Input.Submitted, "#search-input")
    def on_input_submitted(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        if val:
            self.dismiss(val)
        else:
            self.dismiss(CANCEL)


class CommitBrowserApp(App):
    CSS = """
    Screen {
        layout: horizontal;
    }

    #groups-container {
        width: 25%;
        height: 100%;
        border-right: heavy $accent;
    }

    #shas-container {
        width: 30%;
        height: 100%;
        border-right: heavy $accent;
    }

    #commit-container {
        width: 45%;
        height: 100%;
    }

    .panel-title {
        background: $accent;
        color: $text;
        text-align: center;
        text-style: bold;
        width: 100%;
        padding: 0 1;
    }

    OptionList {
        height: 100%;
        border: none;
    }

    #commit-view {
        padding: 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("f", "filter", "Filter"),
        ("s", "search", "Search"),
        ("b", "toggle_blacklist", "Blacklist/Unblacklist"),
        ("B", "toggle_show_blacklisted", "Show/Hide Blacklist"),
        ("tab", "focus_next", "Focus Next Pane"),
        ("shift+tab", "focus_previous", "Focus Prev Pane"),
    ]

    def __init__(self, repo_path: str, db_path: str, blacklist_path: str = "blacklisted_shas.txt"):
        super().__init__()
        self.repo_path = os.path.abspath(os.path.expanduser(repo_path))
        self.db_path = db_path
        self.blacklist_path = os.path.abspath(os.path.expanduser(blacklist_path))
        self.conn = None
        self.group_ids = []
        self.current_shas = []
        self.selected_detection_type = None
        self.target_sha_to_select = None
        self.blacklisted_shas = set()
        self.show_blacklisted = True

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="groups-container"):
                yield Label("Group Section (All)", id="groups-title", classes="panel-title")
                yield OptionList(id="groups-list")
            with Vertical(id="shas-container"):
                yield Label("SHA Section", classes="panel-title")
                yield OptionList(id="shas-list")
            with Vertical(id="commit-container"):
                yield Label("Commit Content", classes="panel-title")
                with ScrollableContainer():
                    yield Static(id="commit-view", expand=True)
        yield Footer()

    def load_blacklist(self) -> None:
        self.blacklisted_shas = set()
        if os.path.exists(self.blacklist_path):
            try:
                with open(self.blacklist_path, "r") as f:
                    for line in f:
                        sha = line.strip().lower()
                        if sha:
                            self.blacklisted_shas.add(sha)
            except Exception as e:
                self.notify(f"Failed to load blacklist: {e}", severity="error")

    def save_blacklist(self) -> None:
        try:
            with open(self.blacklist_path, "w") as f:
                for sha in sorted(self.blacklisted_shas):
                    f.write(f"{sha}\n")
        except Exception as e:
            self.notify(f"Failed to save blacklist: {e}", severity="error")

    def on_mount(self) -> None:
        if not os.path.exists(self.repo_path):
            self.exit(message=f"Error: Repository path '{self.repo_path}' does not exist.")
            return

        if not os.path.exists(self.db_path):
            self.exit(message=f"Error: Database file '{self.db_path}' does not exist.")
            return

        self.conn = sqlite3.connect(self.db_path)
        self.load_blacklist()
        self.update_group_title()
        self.load_groups()

    def action_toggle_show_blacklisted(self) -> None:
        self.show_blacklisted = not self.show_blacklisted
        status = "showing" if self.show_blacklisted else "hiding"
        self.notify(f"Now {status} blacklisted items", severity="information")
        self.update_group_title()

        groups_list = self.query_one("#groups-list", OptionList)
        current_gid = (
            self.group_ids[groups_list.highlighted]
            if groups_list.highlighted is not None
            and 0 <= groups_list.highlighted < len(self.group_ids)
            else None
        )
        self.load_groups(target_gid=current_gid)

    def action_toggle_blacklist(self) -> None:
        focused = self.focused
        if not focused or not self.conn:
            return

        if focused.id == "groups-list":
            groups_list = self.query_one("#groups-list", OptionList)
            if (
                groups_list.highlighted is not None
                and 0 <= groups_list.highlighted < len(self.group_ids)
            ):
                gid = self.group_ids[groups_list.highlighted]
                cur = self.conn.cursor()
                cur.execute(
                    "SELECT lower(hex(hash_value)) FROM hashes WHERE group_id = ?",
                    (gid,),
                )
                shas_in_group = [r[0] for r in cur.fetchall()]

                all_blacklisted = all(sha in self.blacklisted_shas for sha in shas_in_group)
                if all_blacklisted:
                    self.blacklisted_shas.difference_update(shas_in_group)
                    self.notify(f"Unblacklisted Group #{gid}", severity="information")
                else:
                    self.blacklisted_shas.update(shas_in_group)
                    self.notify(f"Blacklisted Group #{gid}", severity="information")

                self.save_blacklist()
                self.load_groups(target_gid=gid)

        elif focused.id == "shas-list":
            shas_list = self.query_one("#shas-list", OptionList)
            if (
                shas_list.highlighted is not None
                and 0 <= shas_list.highlighted < len(self.current_shas)
            ):
                sha = self.current_shas[shas_list.highlighted]
                if sha in self.blacklisted_shas:
                    self.blacklisted_shas.remove(sha)
                    self.notify(f"Unblacklisted SHA {sha[:10]}", severity="information")
                else:
                    self.blacklisted_shas.add(sha)
                    self.notify(f"Blacklisted SHA {sha[:10]}", severity="information")

                self.save_blacklist()

                groups_list = self.query_one("#groups-list", OptionList)
                current_gid = (
                    self.group_ids[groups_list.highlighted]
                    if groups_list.highlighted is not None
                    and 0 <= groups_list.highlighted < len(self.group_ids)
                    else None
                )
                self.target_sha_to_select = sha
                self.load_groups(target_gid=current_gid)
                self.query_one("#shas-list", OptionList).focus()

    def action_filter(self) -> None:
        def apply_filter(result):
            if result is CANCEL:
                return
            self.selected_detection_type = result
            self.update_group_title()
            self.load_groups()

        self.push_screen(FilterModal(self.selected_detection_type), apply_filter)

    def action_search(self) -> None:
        def perform_search(sha_query):
            if sha_query is CANCEL or not sha_query or not self.conn:
                return

            where_conditions = ["lower(hex(hash_value)) LIKE ?"]
            params = [f"{sha_query.lower()}%"]

            if not self.show_blacklisted and self.blacklisted_shas:
                placeholders = ",".join("?" for _ in self.blacklisted_shas)
                where_conditions.append(f"lower(hex(hash_value)) NOT IN ({placeholders})")
                params.extend(list(self.blacklisted_shas))

            where_clause = " WHERE " + " AND ".join(where_conditions)

            cur = self.conn.cursor()
            cur.execute(
                f"SELECT group_id, lower(hex(hash_value)) FROM hashes {where_clause}",
                params,
            )
            match = cur.fetchone()

            if not match:
                self.notify(f"No matching SHA '{sha_query}' found.", severity="warning")
                return

            target_gid, target_sha = match

            self.selected_detection_type = None
            self.update_group_title()

            self.target_sha_to_select = target_sha
            self.load_groups(target_gid=target_gid)

            self.query_one("#shas-list", OptionList).focus()

        self.push_screen(SearchModal(), perform_search)

    def update_group_title(self) -> None:
        title_label = self.query_one("#groups-title", Label)
        dt_str = (
            "All"
            if self.selected_detection_type is None
            else DETECTION_NAMES.get(self.selected_detection_type, "Filtered")
        )
        blk_str = " [Show Blacklist]" if self.show_blacklisted else ""
        title_label.update(f"Group Section ({dt_str}){blk_str}")

    def load_groups(self, target_gid: int | None = None) -> None:
        if not self.conn:
            return

        where_conditions = []
        params = []

        if self.selected_detection_type is not None:
            where_conditions.append("detection_type = ?")
            params.append(self.selected_detection_type)

        if not self.show_blacklisted and self.blacklisted_shas:
            placeholders = ",".join("?" for _ in self.blacklisted_shas)
            where_conditions.append(f"lower(hex(hash_value)) NOT IN ({placeholders})")
            params.extend(list(self.blacklisted_shas))

        where_clause = " WHERE " + " AND ".join(where_conditions) if where_conditions else ""

        cur = self.conn.cursor()
        cur.execute(
            f"""
            SELECT group_id, COUNT(*) as cnt 
            FROM hashes 
            {where_clause}
            GROUP BY group_id 
            ORDER BY cnt DESC, group_id ASC
        """,
            params,
        )
        rows = cur.fetchall()

        groups_list = self.query_one("#groups-list", OptionList)
        groups_list.clear_options()
        self.group_ids = []

        for gid, count in rows:
            self.group_ids.append(gid)

            if self.show_blacklisted and self.blacklisted_shas:
                cur.execute(
                    "SELECT lower(hex(hash_value)) FROM hashes WHERE group_id = ?",
                    (gid,),
                )
                g_shas = [r[0] for r in cur.fetchall()]
                blk_count = sum(1 for s in g_shas if s in self.blacklisted_shas)

                if blk_count == len(g_shas) and len(g_shas) > 0:
                    label = f"[strike]Group #{gid} ({count} members)[/strike] [BLACKLISTED]"
                elif blk_count > 0:
                    label = f"Group #{gid} ({count} members) [{blk_count} BLK]"
                else:
                    label = f"Group #{gid} ({count} members)"
            else:
                label = f"Group #{gid} ({count} members)"

            groups_list.add_option(Option(label, id=str(gid)))

        if self.group_ids:
            gid_idx = (
                self.group_ids.index(target_gid)
                if target_gid is not None and target_gid in self.group_ids
                else 0
            )
            groups_list.highlighted = gid_idx
            self.load_shas_for_group(self.group_ids[gid_idx])
        else:
            self.current_shas = []
            shas_list = self.query_one("#shas-list", OptionList)
            shas_list.clear_options()
            self.query_one("#commit-view", Static).update("")

    def load_shas_for_group(self, group_id: int) -> None:
        cur = self.conn.cursor()

        where_conditions = ["group_id = ?"]
        params = [group_id]

        if self.selected_detection_type is not None:
            where_conditions.append("detection_type = ?")
            params.append(self.selected_detection_type)

        if not self.show_blacklisted and self.blacklisted_shas:
            placeholders = ",".join("?" for _ in self.blacklisted_shas)
            where_conditions.append(f"lower(hex(hash_value)) NOT IN ({placeholders})")
            params.extend(list(self.blacklisted_shas))

        where_clause = " WHERE " + " AND ".join(where_conditions)

        cur.execute(
            f"""
            SELECT lower(hex(hash_value)), detection_type, similarity 
            FROM hashes 
            {where_clause}
        """,
            params,
        )
        rows = cur.fetchall()

        shas_list = self.query_one("#shas-list", OptionList)
        shas_list.clear_options()
        self.current_shas = []

        for sha, dt, sim in rows:
            self.current_shas.append(sha)
            dt_str = DETECTION_NAMES.get(dt, str(dt))
            sim_str = f" | {sim:.2f}" if sim is not None else ""

            if sha in self.blacklisted_shas:
                label = f"[strike]{sha[:10]}[/strike] [{dt_str}{sim_str}] [BLACKLISTED]"
            else:
                label = f"{sha[:10]} [{dt_str}{sim_str}]"

            shas_list.add_option(Option(label, id=sha))

        if self.current_shas:
            highlight_idx = 0
            if (
                self.target_sha_to_select
                and self.target_sha_to_select in self.current_shas
            ):
                highlight_idx = self.current_shas.index(self.target_sha_to_select)
                self.target_sha_to_select = None

            shas_list.highlighted = highlight_idx
            self.show_commit(self.current_shas[highlight_idx])
        else:
            self.query_one("#commit-view", Static).update("")

    def show_commit(self, sha: str) -> None:
        try:
            res = subprocess.run(
                ["git", "show", "--stat", "-p", sha],
                cwd=self.repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                errors="replace",
                timeout=5,
            )
            output = (
                res.stdout
                if res.returncode == 0
                else f"Error running git show:\n{res.stderr}"
            )
        except Exception as e:
            output = f"Failed to execute git show: {e}"

        self.query_one("#commit-view", Static).update(output)

    @on(OptionList.OptionHighlighted, "#groups-list")
    def on_group_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_index is not None and 0 <= event.option_index < len(
            self.group_ids
        ):
            gid = self.group_ids[event.option_index]
            self.load_shas_for_group(gid)

    @on(OptionList.OptionSelected, "#groups-list")
    def on_group_selected(self, event: OptionList.OptionSelected) -> None:
        self.query_one("#shas-list", OptionList).focus()

    @on(OptionList.OptionHighlighted, "#shas-list")
    def on_sha_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_index is not None and 0 <= event.option_index < len(
            self.current_shas
        ):
            sha = self.current_shas[event.option_index]
            self.show_commit(sha)

    def on_unmount(self) -> None:
        if self.conn:
            self.conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TUI browser to inspect git-together commit groups in a repository."
    )
    parser.add_argument(
        "repo_path",
        help="Path to the Linux kernel Git repository.",
    )
    parser.add_argument(
        "--db",
        default="git-together.db",
        help="Path to the SQLite database file.",
    )
    parser.add_argument(
        "--blacklist",
        default="blacklisted_shas.txt",
        help="Path to the blacklisted SHAs text file.",
    )

    args = parser.parse_args()
    app = CommitBrowserApp(args.repo_path, args.db, args.blacklist)
    app.run()