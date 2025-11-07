"""Hayabusa integration view built entirely in Python.

This tab allows operators to load Hayabusa/Yamato YAML rules, select the ones
they want to evaluate, and perform an in-memory scan of Windows EVTX logs
without invoking the external Hayabusa executable.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, List, Optional, Sequence

import yaml
from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from hayabusa_engine import (
    HayabusaRule,
    MatchResult,
    ScanStatistics,
    compile_rules,
    scan_event_logs,
)


class HayabusaScanThread(QThread):
    """Background worker that mimics Hayabusa's scanning pipeline."""

    log_message = Signal(str)
    match_found = Signal(object)
    scan_finished = Signal(int, object)  # status_code, ScanStatistics|None

    def __init__(self, event_source: Path, compiled_rules: Sequence) -> None:
        super().__init__()
        self.event_source = Path(event_source)
        self.compiled_rules = list(compiled_rules)
        self._stop_requested = False
        self._pause_requested = False
        self._pause_lock = threading.Lock()

    # ------------------------------------------------------------------
    def request_stop(self) -> None:
        self._stop_requested = True
        self._pause_requested = False

    # ------------------------------------------------------------------
    def request_pause(self) -> None:
        with self._pause_lock:
            self._pause_requested = True

    # ------------------------------------------------------------------
    def request_resume(self) -> None:
        with self._pause_lock:
            self._pause_requested = False

    # ------------------------------------------------------------------
    def is_paused(self) -> bool:
        with self._pause_lock:
            return self._pause_requested

    # ------------------------------------------------------------------
    def run(self) -> None:  # noqa: D401 (Qt signature)
        try:
            stats = scan_event_logs(
                event_source=self.event_source,
                compiled_rules=self.compiled_rules,
                log_callback=self.log_message.emit,
                match_callback=self.match_found.emit,
                stop_callback=lambda: self._stop_requested,
                pause_callback=lambda: self.is_paused(),
                max_workers=10,
            )
            code = 2 if self._stop_requested else 0
            self.scan_finished.emit(code, stats)
        except Exception as exc:  # pragma: no cover - defensive guard
            self.log_message.emit(f"[ERROR] Scan failed: {exc}")
            self.scan_finished.emit(1, None)


class HayabusaView(QWidget):
    """User interface for Hayabusa rule selection and scanning."""

    STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"]
    LEVELS = ["informational", "low", "medium", "high", "critical"]

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.rules: List[HayabusaRule] = []
        self.filtered_rules: List[HayabusaRule] = []
        self.scan_thread: Optional[HayabusaScanThread] = None
        self.is_scanning = False
        self.is_paused = False
        self.default_event_source = self._detect_default_event_log_path()
        
        # Match queue for throttled UI updates
        self.match_queue: List[MatchResult] = []
        self.all_matches: List[MatchResult] = []  # Store all matches for filtering
        self.match_update_timer = QTimer(self)
        self.match_update_timer.timeout.connect(self._flush_match_queue)
        self.match_update_timer.setInterval(50)  # Update every 50ms to prevent UI freezing

        self._build_ui()
        if self.default_event_source:
            self.event_source_edit.setText(str(self.default_event_source))

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(self._create_setup_group())
        layout.addWidget(self._create_filters_group())
        layout.addWidget(self._create_rules_group())
        layout.addWidget(self._create_execution_group())
        layout.addStretch()

        scroll_area.setWidget(container)
        root_layout.addWidget(scroll_area)

    def _create_setup_group(self) -> QGroupBox:
        group = QGroupBox("Hayabusa Setup")
        form = QFormLayout(group)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        # Rules directory row
        self.rules_dir_edit = QLineEdit()
        self.rules_dir_edit.setPlaceholderText("Directory containing Hayabusa YAML rules")
        browse_rules_btn = QPushButton("Browse…")
        browse_rules_btn.clicked.connect(self._browse_rules_directory)
        load_rules_btn = QPushButton("Load rules")
        load_rules_btn.clicked.connect(self.load_rules_from_directory)
        rules_row = QHBoxLayout()
        rules_row.setContentsMargins(0, 0, 0, 0)
        rules_row.setSpacing(4)
        rules_row.addWidget(self.rules_dir_edit)
        rules_row.addWidget(browse_rules_btn)
        rules_row.addWidget(load_rules_btn)
        form.addRow("Rules directory", rules_row)

        # Event log source row
        self.event_source_edit = QLineEdit()
        self.event_source_edit.setPlaceholderText("Directory or .evtx file to scan")
        browse_event_btn = QPushButton("Browse…")
        browse_event_btn.clicked.connect(self._browse_event_source)
        event_row = self._wrap_with_browse(self.event_source_edit, browse_event_btn)
        form.addRow("Event logs", event_row)

        return group

    def _create_filters_group(self) -> QGroupBox:
        group = QGroupBox("Rule filters (optional)")
        vbox = QVBoxLayout(group)
        vbox.setContentsMargins(8, 8, 8, 8)
        vbox.setSpacing(6)

        status_layout = QHBoxLayout()
        status_layout.setSpacing(8)
        status_layout.addWidget(QLabel("Status:"))
        self.status_checkboxes: dict[str, QCheckBox] = {}
        checkbox_style = """
            QCheckBox::indicator:checked {
                background-color: #28a745;
                border: 1px solid #1e7e34;
            }
        """
        for status in self.STATUSES:
            checkbox = QCheckBox(status.title())
            checkbox.setStyleSheet(checkbox_style)
            checkbox.setChecked(True)  # All statuses checked by default
            checkbox.stateChanged.connect(self._apply_filters)
            self.status_checkboxes[status] = checkbox
            status_layout.addWidget(checkbox)
        status_layout.addStretch()
        vbox.addLayout(status_layout)

        level_layout = QHBoxLayout()
        level_layout.setSpacing(8)
        level_layout.addWidget(QLabel("Level:"))
        self.level_checkboxes: dict[str, QCheckBox] = {}
        for level in self.LEVELS:
            checkbox = QCheckBox(level.title())
            checkbox.setStyleSheet(checkbox_style)
            checkbox.setChecked(True)  # All levels checked by default
            checkbox.stateChanged.connect(self._apply_filters)
            self.level_checkboxes[level] = checkbox
            level_layout.addWidget(checkbox)
        level_layout.addStretch()
        vbox.addLayout(level_layout)

        # Noisy rule filter
        noisy_layout = QHBoxLayout()
        noisy_layout.setSpacing(8)
        self.filter_noisy_checkbox = QCheckBox("Exclude noisy rules")
        self.filter_noisy_checkbox.setStyleSheet(checkbox_style)
        self.filter_noisy_checkbox.setChecked(False)  # Default to unchecked
        self.filter_noisy_checkbox.setToolTip(
            "Excludes rules that have '(noisy)' in their name/title"
        )
        self.filter_noisy_checkbox.stateChanged.connect(self._apply_filters)
        noisy_layout.addWidget(self.filter_noisy_checkbox)
        noisy_layout.addStretch()
        vbox.addLayout(noisy_layout)

        return group

    def _create_rules_group(self) -> QGroupBox:
        group = QGroupBox("Rules")
        group_layout = QVBoxLayout(group)
        group_layout.setContentsMargins(8, 8, 8, 8)
        group_layout.setSpacing(6)

        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(6)
        self.select_all_btn = QPushButton("Select all")
        self.select_all_btn.clicked.connect(self.select_all_rules)
        self.clear_selection_btn = QPushButton("Clear selection")
        self.clear_selection_btn.clicked.connect(self.clear_rule_selection)
        controls_layout.addWidget(self.select_all_btn)
        controls_layout.addWidget(self.clear_selection_btn)
        controls_layout.addStretch()
        group_layout.addLayout(controls_layout)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setMinimumHeight(400)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.rules_tree = QTreeWidget()
        self.rules_tree.setColumnCount(4)
        self.rules_tree.setHeaderLabels(["Title", "Level", "Status", "File"])
        self.rules_tree.setAlternatingRowColors(True)
        self.rules_tree.setRootIsDecorated(False)
        self.rules_tree.setAllColumnsShowFocus(True)
        self.rules_tree.itemChanged.connect(self._handle_rule_item_changed)
        self.rules_tree.currentItemChanged.connect(self._update_rule_details)
        self.rules_tree.itemSelectionChanged.connect(self._handle_tree_selection_changed)

        self.rule_details = QPlainTextEdit()
        self.rule_details.setReadOnly(True)
        self.rule_details.setPlaceholderText("Select a rule to see its details")

        splitter.addWidget(self.rules_tree)
        splitter.addWidget(self.rule_details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        group_layout.addWidget(splitter)

        self.rules_summary_label = QLabel("No rules loaded")
        group_layout.addWidget(self.rules_summary_label)

        return group

    def _create_execution_group(self) -> QGroupBox:
        group = QGroupBox("Execution")
        vbox = QVBoxLayout(group)
        vbox.setContentsMargins(8, 8, 8, 8)
        vbox.setSpacing(6)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(6)
        self.start_scan_btn = QPushButton("Run scan")
        self.start_scan_btn.setProperty("role", "primary")
        self.start_scan_btn.clicked.connect(self.start_scan)
        self.pause_scan_btn = QPushButton("Pause")
        self.pause_scan_btn.setEnabled(False)
        self.pause_scan_btn.clicked.connect(self.toggle_pause)
        self.cancel_scan_btn = QPushButton("Cancel")
        self.cancel_scan_btn.setEnabled(False)
        self.cancel_scan_btn.clicked.connect(self.cancel_scan)
        btn_layout.addWidget(self.start_scan_btn)
        btn_layout.addWidget(self.pause_scan_btn)
        btn_layout.addWidget(self.cancel_scan_btn)
        btn_layout.addStretch()
        vbox.addLayout(btn_layout)

        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        self.scan_progress.setRange(0, 0)  # Indeterminate by default
        vbox.addWidget(self.scan_progress)

        matches_label = QLabel("Matches")
        vbox.addWidget(matches_label)

        # Match table filters
        match_filter_layout = QHBoxLayout()
        match_filter_layout.setSpacing(8)
        match_filter_layout.addWidget(QLabel("Filter by criticality:"))
        self.match_level_checkboxes: dict[str, QCheckBox] = {}
        checkbox_style = """
            QCheckBox::indicator:checked {
                background-color: #28a745;
                border: 1px solid #1e7e34;
            }
        """
        for level in self.LEVELS:
            checkbox = QCheckBox(level.title())
            checkbox.setStyleSheet(checkbox_style)
            checkbox.setChecked(True)  # All levels checked by default
            checkbox.stateChanged.connect(self._filter_matches_table)
            self.match_level_checkboxes[level] = checkbox
            match_filter_layout.addWidget(checkbox)
        match_filter_layout.addStretch()
        vbox.addLayout(match_filter_layout)

        self.matches_tree = QTreeWidget()
        self.matches_tree.setColumnCount(7)
        self.matches_tree.setHeaderLabels([
            "Rule",
            "Criticality",
            "EventID",
            "Channel",
            "Computer",
            "Time",
            "Source file",
        ])
        self.matches_tree.setAlternatingRowColors(True)
        self.matches_tree.setRootIsDecorated(False)
        self.matches_tree.setAllColumnsShowFocus(True)
        self.matches_tree.currentItemChanged.connect(self._display_match_details)
        self.matches_tree.setMinimumHeight(300)
        self.matches_tree.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        vbox.addWidget(self.matches_tree, stretch=3)

        details_label = QLabel("Match details")
        vbox.addWidget(details_label)

        self.match_details = QPlainTextEdit()
        self.match_details.setReadOnly(True)
        self.match_details.setPlaceholderText("Select a match to view full event data")
        self.match_details.setMinimumHeight(200)
        self.match_details.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        vbox.addWidget(self.match_details, stretch=2)

        log_label = QLabel("Scan log")
        vbox.addWidget(log_label)

        self.output_log = QPlainTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setPlaceholderText("Hayabusa scan output will appear here")
        self.output_log.setMinimumHeight(80)
        self.output_log.setMaximumHeight(150)
        vbox.addWidget(self.output_log, stretch=1)

        return group

    # ------------------------------------------------------------------
    # Helper builders
    # ------------------------------------------------------------------
    @staticmethod
    def _wrap_with_browse(line_edit: QLineEdit, button: QPushButton) -> QHBoxLayout:
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(line_edit)
        layout.addWidget(button)
        return layout

    # ------------------------------------------------------------------
    def _detect_default_event_log_path(self) -> Optional[Path]:
        windir = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if not windir:
            return None
        candidate = Path(windir) / "System32" / "winevt" / "Logs"
        return candidate if candidate.exists() else None

    # ------------------------------------------------------------------
    # Browsers / pickers
    # ------------------------------------------------------------------
    def _browse_rules_directory(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Hayabusa rules directory",
            "",
        )
        if directory:
            self.rules_dir_edit.setText(directory)

    def _browse_event_source(self) -> None:
        initial_dir = str(self.default_event_source) if self.default_event_source else ""
        options = "Event logs (*.evtx);;All files (*.*)"
        event_path, _ = QFileDialog.getOpenFileName(self, "Select event log", initial_dir, options)
        if event_path:
            self.event_source_edit.setText(event_path)
            return

        directory = QFileDialog.getExistingDirectory(self, "Select event log directory", initial_dir)
        if directory:
            self.event_source_edit.setText(directory)

    # ------------------------------------------------------------------
    # Rule handling
    # ------------------------------------------------------------------
    def load_rules_from_directory(self) -> None:
        directory_text = self.rules_dir_edit.text().strip()
        directory = Path(directory_text)
        if not directory_text or not directory.exists() or not directory.is_dir():
            QMessageBox.warning(
                self,
                "Invalid rules directory",
                "Please select a valid directory that contains Hayabusa YAML rules.",
            )
            return

        candidates = list(directory.rglob("*.yml")) + list(directory.rglob("*.yaml"))
        if not candidates:
            QMessageBox.information(
                self,
                "No rules found",
                "The selected directory does not contain any .yml or .yaml files.",
            )
            return

        loaded_rules: List[HayabusaRule] = []
        parse_failures: List[str] = []

        for path in sorted(candidates):
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as handle:
                    data = yaml.safe_load(handle)
            except yaml.YAMLError as exc:
                parse_failures.append(f"{path.name}: {exc}")
                continue
            except Exception as exc:  # pragma: no cover - defensive
                parse_failures.append(f"{path.name}: {exc}")
                continue

            if isinstance(data, list):
                rule_dict = data[0] if data else None
            else:
                rule_dict = data

            if not isinstance(rule_dict, dict):
                parse_failures.append(f"{path.name}: unexpected YAML structure")
                continue

            title = str(rule_dict.get("title") or path.stem)
            level = str(rule_dict.get("level") or "unknown").lower()
            status = str(rule_dict.get("status") or "unknown").lower()
            description = str(rule_dict.get("description") or "")
            rule_id = rule_dict.get("id") or rule_dict.get("rule_id")

            loaded_rules.append(
                HayabusaRule(
                    title=title,
                    path=path,
                    level=level,
                    status=status,
                    rule_id=str(rule_id) if rule_id else None,
                    description=description,
                    raw=rule_dict,
                )
            )

        self.rules = loaded_rules
        self.filtered_rules = list(self.rules)
        self._populate_rule_tree()

        summary = f"Loaded {len(self.rules)} rules from {directory}"
        if parse_failures:
            summary += f" (skipped {len(parse_failures)} malformed files)"
            self._append_log("\n".join(f"[WARN] {failure}" for failure in parse_failures))
        self.rules_summary_label.setText(summary)

    def _collect_checked_rule_paths(self) -> set[Path]:
        checked: set[Path] = set()
        for index in range(self.rules_tree.topLevelItemCount()):
            item = self.rules_tree.topLevelItem(index)
            rule = item.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(rule, HayabusaRule) and item.checkState(0) == Qt.CheckState.Checked:
                checked.add(rule.path)
        return checked

    def _populate_rule_tree(self, preserve_selection: bool = False) -> None:
        rules_to_show = self.filtered_rules if self.filtered_rules else self.rules
        if preserve_selection:
            checked_paths = self._collect_checked_rule_paths()
        else:
            checked_paths = set()

        self.rules_tree.blockSignals(True)
        self.rules_tree.clear()

        for rule in rules_to_show:
            item = QTreeWidgetItem(self.rules_tree)
            item.setText(0, rule.title)
            item.setText(1, rule.level)
            item.setText(2, rule.status)
            item.setText(3, rule.path.name)
            item.setData(0, Qt.ItemDataRole.UserRole, rule)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable)
            if rule.path in checked_paths:
                item.setCheckState(0, Qt.CheckState.Checked)
            else:
                item.setCheckState(0, Qt.CheckState.Unchecked)

        for column in range(4):
            self.rules_tree.resizeColumnToContents(column)

        self.rules_tree.blockSignals(False)
        self._update_selection_summary()
        self.rule_details.clear()

    def _apply_filters(self) -> None:
        status_filter = [status for status, cb in self.status_checkboxes.items() if cb.isChecked()]
        level_filter = [level for level, cb in self.level_checkboxes.items() if cb.isChecked()]
        exclude_noisy = self.filter_noisy_checkbox.isChecked()

        filtered: List[HayabusaRule] = []
        for rule in self.rules:
            # Apply status filter
            if status_filter and rule.status not in status_filter:
                continue
            # Apply level filter
            if level_filter and rule.level not in level_filter:
                continue
            
            # Apply noisy filter ONLY if checkbox is checked
            # Only exclude rules that have "(noisy)" exactly in the title (case-insensitive)
            if exclude_noisy:
                rule_title_lower = rule.title.lower()
                # Check for "(noisy)" exactly - no other variations
                if "(noisy)" in rule_title_lower:
                    continue  # Skip this rule - it has "(noisy)" in the name
            
            # Rule passed all filters, add it
            filtered.append(rule)

        self.filtered_rules = filtered if filtered else list(self.rules)
        self._populate_rule_tree(preserve_selection=True)

    def select_all_rules(self) -> None:
        self._set_all_rule_checkstates(Qt.CheckState.Checked)

    def clear_rule_selection(self) -> None:
        self._set_all_rule_checkstates(Qt.CheckState.Unchecked)

    def _set_all_rule_checkstates(self, state: Qt.CheckState) -> None:
        self.rules_tree.blockSignals(True)
        for index in range(self.rules_tree.topLevelItemCount()):
            item = self.rules_tree.topLevelItem(index)
            item.setCheckState(0, state)
        self.rules_tree.blockSignals(False)
        self._update_selection_summary()

    def _handle_rule_item_changed(self, item: QTreeWidgetItem, column: int) -> None:  # noqa: D401
        if column == 0:
            self._update_selection_summary()

    def _update_selection_summary(self) -> None:
        selected = self._get_selected_rules()
        total = len(self.filtered_rules) if self.filtered_rules else len(self.rules)
        self.rules_summary_label.setText(
            f"Selected {len(selected)} of {total} displayed rules"
        )

    def _handle_tree_selection_changed(self) -> None:
        self._update_selection_summary()

    def _update_rule_details(self, current: Optional[QTreeWidgetItem], previous: Optional[QTreeWidgetItem]) -> None:  # noqa: D401
        del previous  # Unused
        if not current:
            self.rule_details.clear()
            return
        rule: HayabusaRule = current.data(0, Qt.ItemDataRole.UserRole)
        details = [f"Title: {rule.title}"]
        if rule.rule_id:
            details.append(f"ID: {rule.rule_id}")
        details.append(f"Level: {rule.level}")
        details.append(f"Status: {rule.status}")
        details.append(f"File: {rule.path}")
        if rule.description:
            details.append("")
            details.append(rule.description)
        self.rule_details.setPlainText("\n".join(details))

    def _get_selected_rules(self) -> List[HayabusaRule]:
        checked: List[HayabusaRule] = []
        for index in range(self.rules_tree.topLevelItemCount()):
            item = self.rules_tree.topLevelItem(index)
            if item.checkState(0) == Qt.CheckState.Checked:
                rule = item.data(0, Qt.ItemDataRole.UserRole)
                if isinstance(rule, HayabusaRule):
                    checked.append(rule)

        if checked:
            return checked

        highlighted: List[HayabusaRule] = []
        for item in self.rules_tree.selectedItems():
            rule = item.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(rule, HayabusaRule) and rule not in highlighted:
                highlighted.append(rule)
        return highlighted

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------
    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            return

        event_source_text = self.event_source_edit.text().strip()
        if not event_source_text and self.default_event_source:
            event_source = self.default_event_source
            self.event_source_edit.setText(str(event_source))
        elif event_source_text:
            event_source = Path(event_source_text)
        else:
            event_source = None

        if not event_source or not event_source.exists():
            QMessageBox.warning(
                self,
                "Invalid event source",
                "Please select a valid directory or .evtx file to scan.",
            )
            return

        selected_rules = self._get_selected_rules()
        if not selected_rules:
            QMessageBox.information(
                self,
                "No rules selected",
                "Please select at least one rule to run Hayabusa.",
            )
            return

        self.output_log.clear()
        self.match_details.clear()
        self.matches_tree.clear()
        self.match_queue.clear()
        self.all_matches.clear()
        self.match_update_timer.stop()
        self.is_paused = False
        self.scan_progress.setVisible(True)
        self._set_scanning_state(True)

        compiled_rules, warnings = compile_rules(
            selected_rules,
            include_status=None,
            include_levels=None,
        )

        for warning in warnings:
            self._append_log(f"[WARN] {warning}")

        if not compiled_rules:
            self._append_log("[WARN] No rules available after applying filters.")
            self._set_scanning_state(False)
            self.scan_progress.setVisible(False)
            return

        self.scan_thread = HayabusaScanThread(event_source=event_source, compiled_rules=compiled_rules)
        self.scan_thread.log_message.connect(self._append_log)
        self.scan_thread.match_found.connect(self._handle_match_found)
        self.scan_thread.scan_finished.connect(self._handle_scan_finished)
        self.scan_thread.start()

    def cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.request_stop()
            self.is_paused = False

    def toggle_pause(self) -> None:
        if not self.scan_thread or not self.scan_thread.isRunning():
            return
        
        if self.is_paused:
            self.scan_thread.request_resume()
            self.is_paused = False
            self.pause_scan_btn.setText("Pause")
            self._append_log("[INFO] Scan resumed.")
        else:
            self.scan_thread.request_pause()
            self.is_paused = True
            self.pause_scan_btn.setText("Resume")
            self._append_log("[INFO] Scan paused.")

    def _handle_match_found(self, match: MatchResult) -> None:
        # Add match to queue immediately
        self.match_queue.append(match)
        
        # Always use timer for processing to avoid blocking UI thread
        if not self.match_update_timer.isActive():
            self.match_update_timer.start()

    def _add_match_to_tree(self, match: MatchResult) -> None:
        """Add a single match to the tree immediately."""
        item = QTreeWidgetItem(self.matches_tree)
        event = match.event
        event_id = event.get("EventID", "")
        channel = event.get("Channel", "")
        computer = event.get("Computer", event.get("ComputerName", ""))
        time_created = event.get("TimeCreated", "")

        item.setText(0, match.rule.title)
        item.setText(1, match.rule.level.title())  # Criticality
        item.setText(2, str(event_id))
        item.setText(3, str(channel))
        item.setText(4, str(computer))
        item.setText(5, str(time_created))
        item.setText(6, match.source_path.name)
        item.setData(0, Qt.ItemDataRole.UserRole, match)

        # Resize columns
        for column in range(7):
            self.matches_tree.resizeColumnToContents(column)

        # Log the match
        self._append_log(
            f"[MATCH] {match.rule.title} | Event {event_id} | {computer or 'Unknown host'}"
        )

    def _flush_match_queue(self) -> None:
        if not self.match_queue:
            self.match_update_timer.stop()
            return

        # Process smaller batches to prevent UI freezing
        batch = self.match_queue[:3]  # Process up to 3 matches at a time
        self.match_queue = self.match_queue[3:]

        if not batch:
            return

        # Store matches for filtering
        self.all_matches.extend(batch)

        # Get current filter settings
        level_filter = [level.lower() for level, cb in self.match_level_checkboxes.items() if cb.isChecked()]
        
        # Filter matches based on criticality
        filtered_batch = []
        for match in batch:
            if not level_filter or match.rule.level.lower() in level_filter:
                filtered_batch.append(match)

        # Add filtered matches to tree with minimal UI blocking
        self.matches_tree.setUpdatesEnabled(False)
        for match in filtered_batch:
            item = QTreeWidgetItem(self.matches_tree)
            event = match.event
            event_id = event.get("EventID", "")
            channel = event.get("Channel", "")
            computer = event.get("Computer", event.get("ComputerName", ""))
            time_created = event.get("TimeCreated", "")

            item.setText(0, match.rule.title)
            item.setText(1, match.rule.level.title())  # Criticality
            item.setText(2, str(event_id))
            item.setText(3, str(channel))
            item.setText(4, str(computer))
            item.setText(5, str(time_created))
            item.setText(6, match.source_path.name)
            item.setData(0, Qt.ItemDataRole.UserRole, match)

        self.matches_tree.setUpdatesEnabled(True)
        
        # Resize columns after each batch to ensure full text is visible
        for column in range(7):
            self.matches_tree.resizeColumnToContents(column)

        # Log summary (non-blocking)
        if len(filtered_batch) == 1:
            match = filtered_batch[0]
            event = match.event
            event_id = event.get("EventID", "")
            computer = event.get("Computer", event.get("ComputerName", ""))
            self._append_log(
                f"[MATCH] {match.rule.title} | Event {event_id} | {computer or 'Unknown host'}"
            )
        elif len(filtered_batch) > 1:
            self._append_log(f"[INFO] Added {len(filtered_batch)} matches to results")

        # Allow UI to update
        QApplication.processEvents()

        # Timer will continue automatically if there are more items in queue
        if not self.match_queue:
            self.match_update_timer.stop()
        elif not self.match_update_timer.isActive():
            # Restart timer if it stopped but there are more items
            self.match_update_timer.start()

    def _filter_matches_table(self) -> None:
        """Filter the matches table based on selected criticality levels."""
        level_filter = [level.lower() for level, cb in self.match_level_checkboxes.items() if cb.isChecked()]
        
        # Clear the tree
        self.matches_tree.clear()
        
        # Filter matches based on criticality
        filtered_matches = []
        for match in self.all_matches:
            if not level_filter or match.rule.level.lower() in level_filter:
                filtered_matches.append(match)
        
        # Repopulate tree with filtered matches
        self.matches_tree.setUpdatesEnabled(False)
        for match in filtered_matches:
            item = QTreeWidgetItem(self.matches_tree)
            event = match.event
            event_id = event.get("EventID", "")
            channel = event.get("Channel", "")
            computer = event.get("Computer", event.get("ComputerName", ""))
            time_created = event.get("TimeCreated", "")

            item.setText(0, match.rule.title)
            item.setText(1, match.rule.level.title())  # Criticality
            item.setText(2, str(event_id))
            item.setText(3, str(channel))
            item.setText(4, str(computer))
            item.setText(5, str(time_created))
            item.setText(6, match.source_path.name)
            item.setData(0, Qt.ItemDataRole.UserRole, match)

        self.matches_tree.setUpdatesEnabled(True)
        
        # Resize columns
        for column in range(7):
            self.matches_tree.resizeColumnToContents(column)

    def _display_match_details(
        self,
        current: Optional[QTreeWidgetItem],
        previous: Optional[QTreeWidgetItem],
    ) -> None:
        del previous  # Unused
        if not current:
            self.match_details.clear()
            return

        match: MatchResult = current.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(match, MatchResult):
            self.match_details.clear()
            return

        details = {
            "rule": match.rule.title,
            "rule_id": match.rule.rule_id,
            "source_file": str(match.source_path),
            "record_id": match.record_id,
            "time_created": match.time_created,
            "event": match.event,
        }
        self.match_details.setPlainText(json.dumps(details, indent=2, ensure_ascii=False))

    def _handle_scan_finished(self, status_code: int, stats: Optional[ScanStatistics]) -> None:
        if status_code == 0:
            self._append_log("[INFO] Scan finished successfully.")
        elif status_code == 2:
            self._append_log("[INFO] Scan cancelled by user.")
        else:
            self._append_log("[ERROR] Scan terminated due to an error.")

        if stats:
            matches_by_rule = ", ".join(
                f"{title}={count}"
                for title, count in sorted(stats.matches_by_rule.items())
            )
            summary = (
                f"Processed {stats.total_events} events across {stats.total_files} files. "
                f"Matches: {stats.total_matches}."
            )
            if matches_by_rule:
                summary += f" Per-rule: {matches_by_rule}."
            self._append_log(f"[INFO] {summary}")

        # Flush any remaining matches in the queue
        while self.match_queue:
            self._flush_match_queue()
        self.match_update_timer.stop()
        
        self.scan_progress.setVisible(False)
        self._set_scanning_state(False)
        self.scan_thread = None

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------
    def _append_log(self, message: str) -> None:
        if not message:
            return
        current = self.output_log.toPlainText()
        if current:
            self.output_log.appendPlainText(message)
        else:
            self.output_log.setPlainText(message)

    def _set_scanning_state(self, is_scanning: bool) -> None:
        self.is_scanning = is_scanning
        self.start_scan_btn.setEnabled(not is_scanning)
        self.pause_scan_btn.setEnabled(is_scanning)
        self.cancel_scan_btn.setEnabled(is_scanning)
        if not is_scanning:
            self.is_paused = False
            self.pause_scan_btn.setText("Pause")



__all__ = ["HayabusaView"]


