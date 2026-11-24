"""Ghostwire Sigma Detection Engine (Module B).

Provides pure-Python Sigma YAML rule ingestion, validation, Ghostwire v2.0.0
schema field mapping, rule enable/disable controls, false-positive exceptions,
ATT&CK tag extraction, and deterministic corpus replay with TP/FP/FN & latency
measurement.
"""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from schema.event_schema import SecurityEvent


class SigmaRuleError(ValueError):
    """Raised when a Sigma rule fails schema or condition validation."""


@dataclass
class RuleException:
    rule_id: str
    field: str
    operator: str  # "exact", "startswith", "contains", "endswith", "regex"
    value: Any
    reason: str = ""

    def matches(self, record: Dict[str, Any]) -> bool:
        actual = _resolve_field(record, self.field)
        if actual is None:
            return False
        return _match_modifier(actual, self.operator, self.value)


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    level: str
    description: str
    tags: List[str]
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    condition: str
    timeframe_seconds: Optional[float] = None
    status: str = "experimental"
    version: str = "1.0.0"
    enabled: bool = True
    falsepositives: List[str] = field(default_factory=list)
    source_path: Optional[str] = None

    @property
    def attack_techniques(self) -> List[str]:
        return [t for t in self.tags if str(t).lower().startswith("attack.")]


@dataclass
class SigmaMatch:
    rule_id: str
    title: str
    level: str
    attack_tags: List[str]
    event_id: Optional[str]
    matched_at: str
    suppressed_by_exception: bool = False
    exception_reason: Optional[str] = None


def _parse_scalar(raw: str) -> Any:
    val = raw.strip()
    if not val:
        return ""
    if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
        return val[1:-1]
    low = val.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    if re.fullmatch(r"-?\d+\.\d+", val):
        return float(val)
    return val


def parse_sigma_yaml(text: str) -> Dict[str, Any]:
    """Parse Sigma YAML rules cleanly (uses PyYAML if available, else built-in parser)."""
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(text)
        if isinstance(loaded, dict):
            return loaded
    except ImportError:
        pass

    lines = text.splitlines()
    root: Dict[str, Any] = {}
    # Stack of (indent, container, parent_dict, parent_key)
    stack: List[Tuple[int, Any, Optional[Dict[str, Any]], Optional[str]]] = [(-1, root, None, None)]
    i = 0
    while i < len(lines):
        raw_line = lines[i]
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        current = stack[-1][1]

        if stripped.startswith("- "):
            item_str = stripped[2:].strip()
            if not isinstance(current, list):
                # Convert empty dict placeholder into list
                parent_dict = stack[-1][2]
                parent_key = stack[-1][3]
                if parent_dict is not None and parent_key is not None and current == {}:
                    new_list: List[Any] = []
                    parent_dict[parent_key] = new_list
                    stack[-1] = (stack[-1][0], new_list, parent_dict, parent_key)
                    current = new_list
                else:
                    raise SigmaRuleError(f"Unexpected YAML list item at line {i + 1}: {raw_line}")
            current.append(_parse_scalar(item_str))
            i += 1
            continue

        if ":" not in stripped:
            i += 1
            continue

        key, rest = stripped.split(":", 1)
        key = key.strip()
        rest = rest.strip()

        if rest in (">", "|", ">-", "|-"):
            fold = rest.startswith(">")
            block_lines: List[str] = []
            i += 1
            block_indent: Optional[int] = None
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip():
                    block_lines.append("")
                    i += 1
                    continue
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if nxt_indent <= indent:
                    break
                if block_indent is None:
                    block_indent = nxt_indent
                block_lines.append(nxt[block_indent:].rstrip())
                i += 1
            text_val = " ".join(x.strip() for x in block_lines if x.strip()) if fold else "\n".join(block_lines)
            if isinstance(current, dict):
                current[key] = text_val
            continue

        if rest == "":
            child: Dict[str, Any] = {}
            if isinstance(current, dict):
                current[key] = child
                stack.append((indent, child, current, key))
            i += 1
            continue

        if isinstance(current, dict):
            current[key] = _parse_scalar(rest)
        i += 1

    return root


def _parse_timeframe(tf: Optional[str]) -> Optional[float]:
    if not tf:
        return None
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(tf).strip().lower())
    if not m:
        raise SigmaRuleError(f"Unsupported timeframe format: {tf!r}")
    num = int(m.group(1))
    unit = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}[m.group(2)]
    return num * unit


def load_sigma_rule_from_text(text: str, source_path: Optional[str] = None) -> SigmaRule:
    data = parse_sigma_yaml(text)
    for req in ("title", "id", "detection"):
        if req not in data or not data[req]:
            raise SigmaRuleError(f"Missing required Sigma field '{req}' in {source_path or '<text>'}")
    detection = data["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaRuleError(f"Sigma detection block must include 'condition' in {source_path or '<text>'}")

    return SigmaRule(
        rule_id=str(data["id"]),
        title=str(data["title"]),
        level=str(data.get("level", "medium")).lower(),
        description=str(data.get("description", "")),
        tags=[str(t) for t in (data.get("tags") or [])],
        logsource=dict(data.get("logsource") or {}),
        detection=dict(detection),
        condition=str(detection["condition"]),
        timeframe_seconds=_parse_timeframe(detection.get("timeframe")),
        status=str(data.get("status", "experimental")),
        version=str(data.get("version") or data.get("date") or "1.0.0"),
        falsepositives=[str(fp) for fp in (data.get("falsepositives") or [])],
        source_path=source_path,
    )


def load_sigma_rules_from_dir(directory: str) -> Tuple[List[SigmaRule], List[Tuple[str, str]]]:
    """Load all .yml/.yaml Sigma rules from a directory. Returns (rules, errors)."""
    rules: List[SigmaRule] = []
    errors: List[Tuple[str, str]] = []
    if not os.path.isdir(directory):
        return rules, errors
    for fname in sorted(os.listdir(directory)):
        if not (fname.endswith(".yml") or fname.endswith(".yaml")):
            continue
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                rules.append(load_sigma_rule_from_text(f.read(), source_path=fpath))
        except Exception as exc:
            errors.append((fpath, str(exc)))
    return rules, errors


def event_to_sigma_record(event: Any) -> Dict[str, Any]:
    """Map either a v2.0.0 SecurityEvent or a raw dict into a flat/nested Sigma-evaluable record."""
    if isinstance(event, SecurityEvent):
        rec: Dict[str, Any] = {
            "schema_version": event.schema_version,
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "agent_id": event.asset_id,
            "asset_id": event.asset_id,
            "event_category": event.event_category,
            "event_action": event.event_action,
            "severity": event.severity,
            "confidence": event.confidence,
            "is_synthetic": event.provenance.is_synthetic,
        }
        rec.update(event.payload)
        if "type" not in rec:
            if event.event_category == "process" and "." in event.event_action:
                act, phase = event.event_action.split(".", 1)
                rec["type"] = "telemetry"
                rec.setdefault("action", act)
                rec.setdefault("phase", phase)
            elif event.event_category == "auth":
                rec["type"] = "server_event"
                rec.setdefault("event", event.event_action)
            else:
                rec["type"] = event.event_category
        return rec
    if isinstance(event, dict):
        return event
    raise SigmaRuleError("Event must be a SecurityEvent or dict")


def _resolve_field(record: Dict[str, Any], field_path: str) -> Any:
    cur: Any = record
    for part in field_path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _match_modifier(actual: Any, modifier: str, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(_match_modifier(actual, modifier, item) for item in expected)
    if modifier == "exact":
        return actual == expected
    actual_str = str(actual)
    exp_str = str(expected)
    if modifier == "startswith":
        return actual_str.startswith(exp_str)
    if modifier == "endswith":
        return actual_str.endswith(exp_str)
    if modifier == "contains":
        return exp_str.lower() in actual_str.lower()
    if modifier == "regex":
        return bool(re.search(exp_str, actual_str))
    return False


def _evaluate_selection(selection: Dict[str, Any], record: Dict[str, Any]) -> bool:
    for raw_key, expected in selection.items():
        parts = raw_key.split("|")
        field_name = parts[0]
        modifiers = parts[1:]
        actual = _resolve_field(record, field_name)
        if actual is None:
            return False
        op = "exact"
        require_all = False
        for mod in modifiers:
            if mod == "all":
                require_all = True
            elif mod in ("startswith", "endswith", "contains", "re", "regex"):
                op = "regex" if mod == "re" else mod
        if require_all and isinstance(expected, list):
            if not all(_match_modifier(actual, op, item) for item in expected):
                return False
        else:
            if not _match_modifier(actual, op, expected):
                return False
    return True


def _parse_epoch(ts_val: Any) -> float:
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str) and ts_val.strip():
        s = ts_val.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s).timestamp()
        except ValueError:
            pass
    return time.time()


class SigmaEngine:
    """Evaluates Ghostwire events against validated Sigma rules with stateful aggregation."""

    def __init__(self, rules: Optional[List[SigmaRule]] = None) -> None:
        self.rules: Dict[str, SigmaRule] = {}
        self.exceptions: Dict[str, List[RuleException]] = defaultdict(list)
        # (rule_id, group_key) -> deque of timestamps
        self._agg_windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        if rules:
            for r in rules:
                self.add_rule(r)

    def add_rule(self, rule: SigmaRule) -> None:
        self.rules[rule.rule_id] = rule

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        if rule_id not in self.rules:
            return False
        self.rules[rule_id].enabled = enabled
        return True

    def add_exception(self, exc: RuleException) -> None:
        self.exceptions[exc.rule_id].append(exc)

    def evaluate_event(self, event: Any) -> List[SigmaMatch]:
        record = event_to_sigma_record(event)
        matches: List[SigmaMatch] = []
        event_id = str(record.get("event_id") or "") or None
        now_iso = datetime.now(timezone.utc).isoformat()

        for rule in self.rules.values():
            if not rule.enabled:
                continue
            if self._evaluate_rule(rule, record):
                suppressed_reason = self._check_exceptions(rule.rule_id, record)
                matches.append(
                    SigmaMatch(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        level=rule.level,
                        attack_tags=rule.attack_techniques,
                        event_id=event_id,
                        matched_at=now_iso,
                        suppressed_by_exception=suppressed_reason is not None,
                        exception_reason=suppressed_reason,
                    )
                )
        return matches

    def _check_exceptions(self, rule_id: str, record: Dict[str, Any]) -> Optional[str]:
        for exc in self.exceptions.get(rule_id, []):
            if exc.matches(record):
                return exc.reason or "Matched false-positive exception"
        return None

    def _evaluate_rule(self, rule: SigmaRule, record: Dict[str, Any]) -> bool:
        cond = rule.condition.strip()
        # Handle aggregation syntax: "<base_cond> | count() by <field> > <threshold>"
        if "|" in cond:
            base_part, agg_part = [p.strip() for p in cond.split("|", 1)]
            if not self._eval_bool_expr(base_part, rule.detection, record):
                return False
            m = re.fullmatch(r"count\(\)\s+by\s+([A-Za-z0-9_.]+)\s*>\s*(\d+)", agg_part)
            if not m:
                raise SigmaRuleError(f"Unsupported Sigma aggregation expression: {agg_part!r}")
            group_field, threshold = m.group(1), int(m.group(2))
            group_val = str(_resolve_field(record, group_field) or "<missing>")
            ts = _parse_epoch(record.get("timestamp"))
            win = self._agg_windows[(rule.rule_id, group_val)]
            win.append(ts)
            if rule.timeframe_seconds is not None:
                cutoff = ts - rule.timeframe_seconds
                while win and win[0] < cutoff:
                    win.popleft()
            return len(win) > threshold

        return self._eval_bool_expr(cond, rule.detection, record)

    def _eval_bool_expr(self, expr: str, detection: Dict[str, Any], record: Dict[str, Any]) -> bool:
        tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+", expr)
        pos = 0

        def eval_sel(name: str) -> bool:
            sel = detection.get(name)
            if not isinstance(sel, dict):
                raise SigmaRuleError(f"Unknown selection {name!r} in condition {expr!r}")
            return _evaluate_selection(sel, record)

        def parse_or() -> bool:
            nonlocal pos
            val = parse_and()
            while pos < len(tokens) and tokens[pos] == "or":
                pos += 1
                rhs = parse_and()
                val = val or rhs
            return val

        def parse_and() -> bool:
            nonlocal pos
            val = parse_not()
            while pos < len(tokens) and tokens[pos] == "and":
                pos += 1
                rhs = parse_not()
                val = val and rhs
            return val

        def parse_not() -> bool:
            nonlocal pos
            if pos < len(tokens) and tokens[pos] == "not":
                pos += 1
                return not parse_not()
            return parse_atom()

        def parse_atom() -> bool:
            nonlocal pos
            if pos >= len(tokens):
                raise SigmaRuleError(f"Unexpected end of condition: {expr!r}")
            tok = tokens[pos]
            if tok == "(":
                pos += 1
                val = parse_or()
                if pos >= len(tokens) or tokens[pos] != ")":
                    raise SigmaRuleError(f"Unmatched '(' in condition: {expr!r}")
                pos += 1
                return val
            pos += 1
            return eval_sel(tok)

        return parse_or()


def evaluate_corpus(
    engine: SigmaEngine,
    corpus: List[Tuple[Any, bool]],
) -> Dict[str, Any]:
    """Run deterministic replay over labeled (event, expected_alert) fixtures and measure TP/FP/FN/latency."""
    tp = fp = fn = tn = 0
    latencies_ms: List[float] = []

    for event, expected_alert in corpus:
        t0 = time.perf_counter()
        matches = [m for m in engine.evaluate_event(event) if not m.suppressed_by_exception]
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

        fired = len(matches) > 0
        if expected_alert and fired:
            tp += 1
        elif not expected_alert and fired:
            fp += 1
        elif expected_alert and not fired:
            fn += 1
        else:
            tn += 1

    total = len(corpus)
    lat_sorted = sorted(latencies_ms)
    p95_idx = min(len(lat_sorted) - 1, int(len(lat_sorted) * 0.95)) if lat_sorted else 0
    total_ms = sum(latencies_ms)
    return {
        "total_events": total,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 1.0,
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else 1.0,
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "avg_latency_ms": round(total_ms / total, 4) if total else 0.0,
        "p95_latency_ms": round(lat_sorted[p95_idx], 4) if lat_sorted else 0.0,
        "throughput_eps": round((total / (total_ms / 1000.0)), 2) if total_ms > 0 else 0.0,
    }
