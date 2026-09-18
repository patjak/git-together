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
from textual.widgets import Footer, Header, Label, OptionList, Static
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
        ("tab", "focus_next", "Focus Next Pane"),
        ("shift+tab", "focus_previous", "Focus Prev Pane"),
    ]

    def __init__(self, repo_path: str, db_path: str):
        super().__init__()
        self.repo_path = os.path.abspath(os.path.expanduser(repo_path))
        self.db_path = db_path
        self.conn = None
        self.group_ids = []
        self.current_shas = []
        self.selected_detection_type = None

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

    def on_mount(self) -> None:
        if not os.path.exists(self.repo_path):
            self.exit(message=f"Error: Repository path '{self.repo_path}' does not exist.")
            return

        if not os.path.exists(self.db_path):
            self.exit(message=f"Error: Database file '{self.db_path}' does not exist.")
            return

        self.conn = sqlite3.connect(self.db_path)
        self.load_groups()

    def action_filter(self) -> None:
        def apply_filter(result):
            if result is CANCEL:
                return
            self.selected_detection_type = result
            self.update_group_title()
            self.load_groups()

        self.push_screen(FilterModal(self.selected_detection_type), apply_filter)

    def update_group_title(self) -> None:
        title_label = self.query_one("#groups-title", Label)
        if self.selected_detection_type is None:
            title_label.update("Group Section (All)")
        else:
            dt_name = DETECTION_NAMES.get(self.selected_detection_type, "Filtered")
            title_label.update(f"Group Section [{dt_name}]")

    def load_groups(self) -> None:
        if not self.conn:
            return
        cur = self.conn.cursor()
        if self.selected_detection_type is not None:
            cur.execute(
                """
                SELECT group_id, COUNT(*) as cnt 
                FROM hashes 
                WHERE detection_type = ?
                GROUP BY group_id 
                ORDER BY cnt DESC, group_id ASC
            """,
                (self.selected_detection_type,),
            )
        else:
            cur.execute(
                """
                SELECT group_id, COUNT(*) as cnt 
                FROM hashes 
                GROUP BY group_id 
                ORDER BY cnt DESC, group_id ASC
            """
            )
        rows = cur.fetchall()

        groups_list = self.query_one("#groups-list", OptionList)
        groups_list.clear_options()
        self.group_ids = []

        for gid, count in rows:
            self.group_ids.append(gid)
            groups_list.add_option(
                Option(f"Group #{gid} ({count} members)", id=str(gid))
            )

        if self.group_ids:
            groups_list.highlighted = 0
            self.load_shas_for_group(self.group_ids[0])
        else:
            self.current_shas = []
            shas_list = self.query_one("#shas-list", OptionList)
            shas_list.clear_options()
            self.query_one("#commit-view", Static).update("")

    def load_shas_for_group(self, group_id: int) -> None:
        cur = self.conn.cursor()
        if self.selected_detection_type is not None:
            cur.execute(
                """
                SELECT lower(hex(hash_value)), detection_type, similarity 
                FROM hashes 
                WHERE group_id = ? AND detection_type = ?
            """,
                (group_id, self.selected_detection_type),
            )
        else:
            cur.execute(
                """
                SELECT lower(hex(hash_value)), detection_type, similarity 
                FROM hashes 
                WHERE group_id = ?
            """,
                (group_id,),
            )
        rows = cur.fetchall()

        shas_list = self.query_one("#shas-list", OptionList)
        shas_list.clear_options()
        self.current_shas = []

        for sha, dt, sim in rows:
            self.current_shas.append(sha)
            dt_str = DETECTION_NAMES.get(dt, str(dt))
            sim_str = f" | {sim:.2f}" if sim is not None else ""
            shas_list.add_option(Option(f"{sha[:10]} [{dt_str}{sim_str}]", id=sha))

        if self.current_shas:
            shas_list.highlighted = 0
            self.show_commit(self.current_shas[0])
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

    args = parser.parse_args()
    app = CommitBrowserApp(args.repo_path, args.db)
    app.run()