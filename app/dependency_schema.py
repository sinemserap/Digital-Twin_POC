"""Value schema of the F01 predicate `preboarding_dependency_status` (PROVISIONAL — decision D-03).

F01 Part 1 §1.1 registers the predicate (ITSM/service authority, needed by F03 HAS_DEPENDENCY
and BLOCKED_BY) but defines no value shape. F01 Part 1 keeps one *current* claim per predicate
and subject (§1.5), so the value is the subject's complete dependency state, as a list:

    {"dependencies": [
        {"task_ref": "TASK-LAPTOP", "label": "Laptop", "status": "blocked",
         "blocked_by": {"task_ref": "REQ-ACCOUNT", "label": "AD account"},
         "reason_code": "DEP_NOT_RESOLVED", "reason": "waiting on account creation"},
        {"task_ref": "TASK-BADGE", "status": "open"}
    ]}

A single dependency object (without the `dependencies` wrapper) is accepted as a one-item
list. `status` is open | in_progress | blocked | resolved; a blocked item requires `blocked_by`
and `reason_code`. References are opaque ticket/task identifiers, never free personal data.

This module is shared by F01 (ledger event emission, extension F01-EXT-01, decision D-04) and by
the F03 projection, so both sides read the value identically.
"""
from __future__ import annotations

DEPENDENCY_STATUSES = frozenset({"open", "in_progress", "blocked", "resolved"})


class InvalidDependencyValue(ValueError):
    pass


def _ref(value, key: str) -> tuple[str, str | None]:
    if isinstance(value, str) and value.strip():
        return value.strip(), None
    if isinstance(value, dict) and isinstance(value.get(key), str) and value[key].strip():
        label = value.get("label")
        if label is not None and not isinstance(label, str):
            raise InvalidDependencyValue(f"{key}: label must be a string")
        return value[key].strip(), label
    raise InvalidDependencyValue(f"expected reference string or object with '{key}'")


def normalize_dependencies(value) -> list[dict]:
    items = value.get("dependencies") if isinstance(value, dict) and "dependencies" in value else value
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list) or not items:
        raise InvalidDependencyValue("preboarding_dependency_status: expected a non-empty dependencies list")
    out, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            raise InvalidDependencyValue("dependency item must be an object")
        task_ref, label = _ref(item, "task_ref")
        status = item.get("status")
        if status not in DEPENDENCY_STATUSES:
            raise InvalidDependencyValue(f"dependency status must be one of {sorted(DEPENDENCY_STATUSES)}")
        if task_ref in seen:
            raise InvalidDependencyValue(f"duplicate task_ref {task_ref}")
        seen.add(task_ref)
        dep = {"task_ref": task_ref, "label": label, "status": status, "blocked_by": None,
               "blocked_by_label": None, "reason_code": None, "reason": None}
        if status == "blocked":
            if "blocked_by" not in item or not isinstance(item.get("reason_code"), str) or not item["reason_code"].strip():
                raise InvalidDependencyValue("blocked dependency requires blocked_by and reason_code")
            dep["blocked_by"], dep["blocked_by_label"] = _ref(item["blocked_by"], "task_ref")
            if dep["blocked_by"] == task_ref:
                raise InvalidDependencyValue("a task cannot be blocked by itself")
            dep["reason_code"] = item["reason_code"].strip()
            reason = item.get("reason")
            if reason is not None and not isinstance(reason, str):
                raise InvalidDependencyValue("reason must be a string")
            dep["reason"] = reason
        out.append(dep)
    return out
