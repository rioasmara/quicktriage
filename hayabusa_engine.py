"""Lightweight Hayabusa-style rule processing for Windows EVTX logs.

This module provides a minimal subset of the functionality offered by the
Hayabusa project: it can load Sigma-like YAML detection rules, compile them
into matchers, and evaluate those matchers against Windows Event Log (EVTX)
records.  The goal is to support interactive exploration from the GUI without
requiring the external Hayabusa executable.

The implementation focuses on the rule constructs that are most common in the
Hayabusa rule corpus: equality matches, string contains/starts/ends-with
operators, basic regular expressions, and AND/OR/NOT conditions across
named selections.  Advanced Sigma features ("1 of", aggregation modifiers,
temporal conditions, etc.) are intentionally out of scope for this initial
integration.
"""

from __future__ import annotations

import re
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from Evtx.Evtx import Evtx


# ---------------------------------------------------------------------------
# Dataclasses exposed to the UI layer
# ---------------------------------------------------------------------------


@dataclass
class HayabusaRule:
    """Container for rule metadata and raw contents."""

    title: str
    path: Path
    level: str
    status: str
    rule_id: Optional[str]
    description: str
    raw: Dict[str, Any]


@dataclass
class MatchResult:
    """Represents a single rule hit against an event."""

    rule: HayabusaRule
    event: Dict[str, Any]
    source_path: Path
    record_id: Optional[int] = None
    time_created: Optional[str] = None


@dataclass
class ScanStatistics:
    """Aggregate metrics for a scan run."""

    total_files: int = 0
    total_events: int = 0
    total_matches: int = 0
    matches_by_rule: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rule compilation support
# ---------------------------------------------------------------------------


class RuleCompilationError(RuntimeError):
    """Raised when a rule cannot be compiled into a matcher."""


class ConditionNode:
    """Abstract syntax tree for detection conditions."""

    def evaluate(self, resolver: Callable[[str], bool]) -> bool:
        raise NotImplementedError


class NameNode(ConditionNode):
    def __init__(self, name: str) -> None:
        self.name = name

    def evaluate(self, resolver: Callable[[str], bool]) -> bool:
        return resolver(self.name)


class AndNode(ConditionNode):
    def __init__(self, left: ConditionNode, right: ConditionNode) -> None:
        self.left = left
        self.right = right

    def evaluate(self, resolver: Callable[[str], bool]) -> bool:
        return self.left.evaluate(resolver) and self.right.evaluate(resolver)


class OrNode(ConditionNode):
    def __init__(self, left: ConditionNode, right: ConditionNode) -> None:
        self.left = left
        self.right = right

    def evaluate(self, resolver: Callable[[str], bool]) -> bool:
        return self.left.evaluate(resolver) or self.right.evaluate(resolver)


class NotNode(ConditionNode):
    def __init__(self, operand: ConditionNode) -> None:
        self.operand = operand

    def evaluate(self, resolver: Callable[[str], bool]) -> bool:
        return not self.operand.evaluate(resolver)


class SelectionClause:
    """Represents an AND-group of field matchers."""

    def __init__(self, matchers: Sequence["FieldMatcher"]) -> None:
        self.matchers = list(matchers)

    def matches(self, event: Dict[str, Any]) -> bool:
        return all(matcher.matches(event) for matcher in self.matchers)


class FieldMatcher:
    """Implements a single field comparison or string operation."""

    def __init__(self, field: str, modifiers: Sequence[str], raw_value: Any) -> None:
        self.field = field
        self.modifiers = [modifier.lower() for modifier in modifiers]
        self.match_all = False
        if "all" in self.modifiers:
            self.match_all = True
            self.modifiers = [modifier for modifier in self.modifiers if modifier != "all"]

        if isinstance(raw_value, (list, tuple, set)):
            self.values = list(raw_value)
        else:
            self.values = [raw_value]

        if any(mod in {"re", "regex", "regexp"} for mod in self.modifiers):
            self.regexes = [
                re.compile(str(value), re.IGNORECASE)
                for value in self.values
            ]
        else:
            self.regexes = []

    # ------------------------------------------------------------------
    def matches(self, event: Dict[str, Any]) -> bool:
        value = event.get(self.field)
        if value is None:
            return False

        values: Sequence[Any]
        if isinstance(value, (list, tuple, set)):
            values = list(value)
        else:
            values = [value]

        if self.match_all:
            return all(self._value_matches_any(values, expected) for expected in self.values)
        return any(self._value_matches_any(values, expected) for expected in self.values)

    # ------------------------------------------------------------------
    def _value_matches_any(self, actual_values: Sequence[Any], expected: Any) -> bool:
        for actual in actual_values:
            if self._single_value_matches(actual, expected):
                return True
        return False

    # ------------------------------------------------------------------
    def _single_value_matches(self, actual: Any, expected: Any) -> bool:
        if actual is None:
            return False

        if self.regexes:
            for regex in self.regexes:
                if regex.search(str(actual)):
                    return True
            return False

        actual_str = str(actual)
        expected_str = str(expected)

        if "contains" in self.modifiers:
            return expected_str.lower() in actual_str.lower()
        if "startswith" in self.modifiers:
            return actual_str.lower().startswith(expected_str.lower())
        if "endswith" in self.modifiers:
            return actual_str.lower().endswith(expected_str.lower())

        # Default to equality, attempting numeric comparison first.
        try:
            return float(actual_str) == float(expected_str)
        except ValueError:
            return actual_str.lower() == expected_str.lower()


class CompiledRule:
    """Runtime representation of a compiled Hayabusa rule."""

    def __init__(
        self,
        rule: HayabusaRule,
        selections: Dict[str, List[SelectionClause]],
        condition: ConditionNode,
        logsource: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.rule = rule
        self.selections = selections
        self.condition = condition
        self.logsource = logsource or {}

    # ------------------------------------------------------------------
    def matches(self, event: Dict[str, Any]) -> bool:
        if not self._matches_logsource(event):
            return False

        def resolver(name: str) -> bool:
            clauses = self.selections.get(name)
            if not clauses:
                return False
            return any(clause.matches(event) for clause in clauses)

        return self.condition.evaluate(resolver)

    # ------------------------------------------------------------------
    def _matches_logsource(self, event: Dict[str, Any]) -> bool:
        if not self.logsource:
            return True

        channel = str(event.get("Channel", "")).lower()
        product = str(event.get("Product", "")).lower()
        service = str(event.get("Service", "")).lower()

        if "channel" in self.logsource:
            expected_channel = str(self.logsource["channel"]).lower()
            if channel != expected_channel:
                return False

        if "product" in self.logsource:
            expected_product = str(self.logsource["product"]).lower()
            if expected_product and product:
                if product != expected_product:
                    return False
            # If the event did not populate product information, we allow the rule.

        if "service" in self.logsource:
            expected_service = str(self.logsource["service"]).lower()
            # Many rules reference service "sysmon" while the Channel contains the
            # full provider name. We perform a relaxed comparison that succeeds if
            # the expected keyword appears in the channel path.
            if service:
                if service != expected_service:
                    return False
            elif channel:
                if expected_service not in channel:
                    return False
            # Otherwise allow the rule (e.g., security product without explicit service field).

        if "category" in self.logsource:
            expected_category = str(self.logsource["category"]).lower()
            category = str(event.get("Category", "")).lower()
            # Sigma categories describe logical groupings (process_creation, etc.)
            # which rarely appear verbatim in raw events. We only enforce the
            # comparison when the event provided a matching field.
            if category and category != expected_category:
                return False

        return True


# ---------------------------------------------------------------------------
# Parsing utilities
# ---------------------------------------------------------------------------


def compile_rules(
    rules: Sequence[HayabusaRule],
    include_status: Optional[Sequence[str]] = None,
    include_levels: Optional[Sequence[str]] = None,
) -> Tuple[List[CompiledRule], List[str]]:
    """Compile raw rule documents into executable matchers.

    Args:
        rules: Iterable of loaded rule documents.
        include_status: Optional list of allowed statuses (lower case).
        include_levels: Optional list of allowed severities/levels (lower case).

    Returns:
        (compiled_rules, warnings) where warnings contains human-readable
        messages for rules that were skipped during compilation.
    """

    compiled: List[CompiledRule] = []
    warnings: List[str] = []

    status_filter = {status.lower() for status in include_status or []}
    level_filter = {level.lower() for level in include_levels or []}

    for rule in rules:
        if status_filter and rule.status.lower() not in status_filter:
            continue
        if level_filter and rule.level.lower() not in level_filter:
            continue

        try:
            compiled_rule = _compile_rule(rule)
        except RuleCompilationError as exc:
            warnings.append(f"{rule.title}: {exc}")
            continue
        except Exception as exc:  # Defensive logging for unexpected structures
            warnings.append(f"{rule.title}: unexpected error {exc}")
            continue

        compiled.append(compiled_rule)

    return compiled, warnings


def _compile_rule(rule: HayabusaRule) -> CompiledRule:
    raw_detection = rule.raw.get("detection")
    if not isinstance(raw_detection, dict) or not raw_detection:
        raise RuleCompilationError("missing or invalid detection block")

    selections: Dict[str, List[SelectionClause]] = {}
    for name, value in raw_detection.items():
        if name == "condition":
            continue
        clauses = _build_selection_clauses(value)
        if clauses:
            selections[name] = clauses

    if not selections:
        raise RuleCompilationError("no usable selections in detection block")

    condition_text = raw_detection.get("condition")
    try:
        condition = _parse_condition(condition_text, selections)
    except RuleCompilationError:
        raise
    except Exception as exc:  # pragma: no cover - defensive guard
        raise RuleCompilationError(f"failed to parse condition: {exc}") from exc

    logsource = rule.raw.get("logsource") if isinstance(rule.raw.get("logsource"), dict) else None

    return CompiledRule(rule=rule, selections=selections, condition=condition, logsource=logsource)


def _build_selection_clauses(raw_selection: Any) -> List[SelectionClause]:
    clauses: List[SelectionClause] = []

    if isinstance(raw_selection, dict):
        clauses.append(_build_clause_from_dict(raw_selection))
        return clauses

    if isinstance(raw_selection, list):
        for entry in raw_selection:
            if isinstance(entry, dict):
                clauses.append(_build_clause_from_dict(entry))
            else:
                # Scalar entries are unsupported outside of dict context.
                continue
        return clauses

    # Unsupported structure
    return clauses


def _build_clause_from_dict(data: Dict[str, Any]) -> SelectionClause:
    matchers: List[FieldMatcher] = []
    for key, value in data.items():
        field, modifiers = _split_field_key(key)
        matchers.append(FieldMatcher(field, modifiers, value))
    return SelectionClause(matchers)


def _split_field_key(field_key: str) -> Tuple[str, List[str]]:
    parts = field_key.split("|")
    field = parts[0]
    modifiers = parts[1:] if len(parts) > 1 else []
    return field, modifiers


def _parse_condition(condition_text: Optional[str], selections: Dict[str, Any]) -> ConditionNode:
    names = list(selections.keys())
    if not condition_text:
        if len(names) == 1:
            return NameNode(names[0])
        # Default to OR across all selections
        return _parse_condition(" or ".join(names), selections)

    lowered = condition_text.lower().strip()
    if " of " in lowered or "*" in lowered:
        raise RuleCompilationError("condition uses unsupported Sigma operators")

    tokens = _tokenise_condition(condition_text)
    parser = _ConditionParser(tokens, set(selections.keys()))
    return parser.parse()


def _tokenise_condition(condition: str) -> List[str]:
    token_pattern = re.compile(r"\b\w+\b|[()]")
    return token_pattern.findall(condition)


class _ConditionParser:
    def __init__(self, tokens: List[str], valid_names: set[str]) -> None:
        self.tokens = tokens
        self.valid_names = {name.lower(): name for name in valid_names}
        self.index = 0

    # --------------------------------------------------------------
    def parse(self) -> ConditionNode:
        node = self._parse_expression()
        if self._current_token() is not None:
            raise RuleCompilationError("unexpected token at end of condition")
        return node

    # --------------------------------------------------------------
    def _parse_expression(self) -> ConditionNode:
        node = self._parse_term()
        while True:
            token = self._current_token()
            if token is None:
                break
            if token.lower() == "or":
                self._advance()
                rhs = self._parse_term()
                node = OrNode(node, rhs)
            else:
                break
        return node

    # --------------------------------------------------------------
    def _parse_term(self) -> ConditionNode:
        node = self._parse_factor()
        while True:
            token = self._current_token()
            if token is None:
                break
            if token.lower() == "and":
                self._advance()
                rhs = self._parse_factor()
                node = AndNode(node, rhs)
            else:
                break
        return node

    # --------------------------------------------------------------
    def _parse_factor(self) -> ConditionNode:
        token = self._current_token()
        if token is None:
            raise RuleCompilationError("unexpected end of condition")

        if token.lower() == "not":
            self._advance()
            operand = self._parse_factor()
            return NotNode(operand)

        if token == "(":
            self._advance()
            node = self._parse_expression()
            if self._current_token() != ")":
                raise RuleCompilationError("missing closing parenthesis")
            self._advance()
            return node

        return self._parse_name()

    # --------------------------------------------------------------
    def _parse_name(self) -> ConditionNode:
        token = self._current_token()
        if token is None:
            raise RuleCompilationError("unexpected end when reading selection name")

        lowered = token.lower()
        if lowered not in self.valid_names:
            raise RuleCompilationError(f"unknown selection '{token}' in condition")

        self._advance()
        return NameNode(self.valid_names[lowered])

    # --------------------------------------------------------------
    def _current_token(self) -> Optional[str]:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    # --------------------------------------------------------------
    def _advance(self) -> None:
        self.index += 1


# ---------------------------------------------------------------------------
# EVTX processing
# ---------------------------------------------------------------------------


def scan_event_logs(
    event_source: Path,
    compiled_rules: Sequence[CompiledRule],
    log_callback: Optional[Callable[[str], None]] = None,
    match_callback: Optional[Callable[[MatchResult], None]] = None,
    stop_callback: Optional[Callable[[], bool]] = None,
    pause_callback: Optional[Callable[[], bool]] = None,
    max_workers: int = 1,
) -> ScanStatistics:
    """Scan an EVTX file or directory using pre-compiled rules."""

    stats = ScanStatistics()

    files = _collect_evtx_files(event_source)
    if not files:
        if log_callback:
            log_callback(f"[WARN] No .evtx files found under {event_source}")
        return stats

    if not compiled_rules:
        if log_callback:
            log_callback("[WARN] No compiled rules available for scanning.")
        return stats

    max_workers = max(1, min(len(files), max_workers))
    stop_event = threading.Event()

    def should_stop() -> bool:
        if stop_event.is_set():
            return True
        if stop_callback and stop_callback():
            stop_event.set()
            return True
        return False

    def process_file(file_path: Path) -> Dict[str, Any]:
        local_events = 0
        local_matches = 0
        local_matches_by_rule: Dict[str, int] = {}
        processed = False

        if log_callback:
            log_callback(f"[INFO] Scanning {file_path}")

        if should_stop():
            return {
                "processed": False,
                "events": 0,
                "matches": 0,
                "matches_by_rule": local_matches_by_rule,
            }

        try:
            with Evtx(str(file_path)) as evtx:
                processed = True
                for record in evtx.records():
                    if should_stop():
                        break

                    # Check for pause state and wait if paused
                    while pause_callback and pause_callback():
                        if should_stop():
                            break
                        time.sleep(0.1)  # Sleep 100ms while paused

                    if should_stop():
                        break

                    event = _parse_event_record(record.xml())
                    if not event:
                        continue

                    local_events += 1

                    for rule in compiled_rules:
                        try:
                            if rule.matches(event):
                                local_matches += 1
                                local_matches_by_rule[rule.rule.title] = (
                                    local_matches_by_rule.get(rule.rule.title, 0) + 1
                                )
                                if match_callback:
                                    match_callback(
                                        MatchResult(
                                            rule=rule.rule,
                                            event=event,
                                            source_path=file_path,
                                            record_id=_safe_int(event.get("EventRecordID")),
                                            time_created=str(event.get("TimeCreated", "")) or None,
                                        )
                                    )
                        except Exception as exc:  # pragma: no cover - defensive guard
                            if log_callback:
                                log_callback(
                                    f"[ERROR] Rule '{rule.rule.title}' evaluation failed: {exc}"
                                )
                            continue
        except Exception as exc:
            if log_callback:
                log_callback(f"[ERROR] Failed to read {file_path}: {exc}")

        return {
            "processed": processed,
            "events": local_events,
            "matches": local_matches,
            "matches_by_rule": local_matches_by_rule,
        }

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(process_file, path): path for path in files}

        for future in as_completed(future_to_path):
            result = future.result()
            if result.get("processed"):
                stats.total_files += 1
            stats.total_events += result.get("events", 0)
            stats.total_matches += result.get("matches", 0)
            for title, count in result.get("matches_by_rule", {}).items():
                stats.matches_by_rule[title] = stats.matches_by_rule.get(title, 0) + count

            if should_stop():
                # Consume remaining futures to allow clean shutdown
                for pending in future_to_path:
                    if not pending.done():
                        pending.cancel()
                break

    return stats


def _collect_evtx_files(event_source: Path) -> List[Path]:
    if event_source.is_file():
        return [event_source] if event_source.suffix.lower() == ".evtx" else []

    if not event_source.is_dir():
        return []

    return sorted(p for p in event_source.rglob("*.evtx") if p.is_file())


def _parse_event_record(xml_data: str) -> Dict[str, Any]:
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return {}

    event: Dict[str, Any] = {}

    system = root.find(".//{*}System")
    if system is not None:
        for child in list(system):
            tag = _strip_namespace(child.tag)
            if tag == "Provider":
                name = child.attrib.get("Name")
                if name:
                    event["Provider"] = name
                continue
            if tag == "TimeCreated":
                time_created = child.attrib.get("SystemTime")
                if time_created:
                    event["TimeCreated"] = time_created
                continue
            if tag == "Execution":
                for attr, value in child.attrib.items():
                    event[f"Execution{attr}"] = value
                continue
            if tag == "Security":
                for attr, value in child.attrib.items():
                    event[f"Security{attr}"] = value
                continue

            text = child.text.strip() if child.text else ""
            if tag == "EventID":
                event["EventID"] = _safe_int(text, fallback=text)
            else:
                event[tag] = text

    event_data = root.find(".//{*}EventData")
    if event_data is not None:
        for data_elem in event_data.findall("{*}Data"):
            key = data_elem.attrib.get("Name")
            value = data_elem.text.strip() if data_elem.text else ""
            if not key:
                continue
            _store_value(event, key, value)

    user_data = root.find(".//{*}UserData")
    if user_data is not None:
        for element in user_data.iter():
            if element is user_data:
                continue
            key_attr = element.attrib.get("Name")
            key = key_attr or _strip_namespace(element.tag)
            value = element.text.strip() if element.text else ""
            if value:
                _store_value(event, key, value)

    return event


def _strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _store_value(container: Dict[str, Any], key: str, value: Any) -> None:
    if key in container:
        existing = container[key]
        if isinstance(existing, list):
            existing.append(value)
        else:
            container[key] = [existing, value]
    else:
        container[key] = value


def _safe_int(value: Any, fallback: Optional[Any] = None) -> Optional[int]:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return fallback


__all__ = [
    "HayabusaRule",
    "MatchResult",
    "ScanStatistics",
    "compile_rules",
    "scan_event_logs",
]


