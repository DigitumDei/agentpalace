#!/usr/bin/env python3
"""Extract allowlisted diagnostics; never publish Claude's raw execution log."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

MAX_INPUT_BYTES = 64 * 1024 * 1024
TOOLS = frozenset({
    "Agent", "Task", "TaskOutput", "TaskStop", "Skill", "Bash", "Read", "Write",
    "Edit", "MultiEdit", "Glob", "Grep", "LS", "TodoWrite", "WebFetch", "WebSearch",
    "NotebookEdit", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode",
    "mcp__github_inline_comment__create_inline_comment",
    "mcp__github_comment__update_claude_comment",
    "mcp__github_ci__get_ci_status",
    "mcp__github_ci__get_workflow_run_details",
    "mcp__github_ci__download_job_log",
})
RESULT_TYPES = frozenset({
    "success", "error_during_execution", "error_max_turns",
    "error_max_budget_usd", "error_max_structured_output_retries",
})
# Output labels come only from these constants, never from matched input.
COMMANDS = {
    "gh pr view": r"gh\s+pr\s+view",
    "gh pr diff": r"gh\s+pr\s+diff",
    "gh pr comment": r"gh\s+pr\s+comment",
    "gh pr review": r"gh\s+pr\s+review",
    "gh api": r"gh\s+api",
    "git show": r"git\s+show",
    "git diff": r"git\s+diff",
    "git log": r"git\s+log",
    "git status": r"git\s+status",
    "git grep": r"git\s+grep",
    "git ls-files": r"git\s+ls-files",
    "git rev-parse": r"git\s+rev-parse",
    "git add": r"git\s+add",
    "git commit": r"git\s+commit",
    "git push": r"git\s+push",
    "git rm": r"git\s+rm",
    **{name: re.escape(name) for name in (
        "ls", "cat", "sed", "awk", "grep", "rg", "find", "head", "tail", "wc",
        "test", "pwd", "cd", "python", "python3", "node", "bash", "curl", "jq",
    )},
}


def tool_name(value):
    return value if isinstance(value, str) and value in TOOLS else "other"


def command_categories(value):
    if not isinstance(value, str):
        return ["unclassified"]
    # Diagnostic hints, not a shell parser or an authorization decision.
    return [
        label for label, pattern in COMMANDS.items()
        if re.search(r"(?:^|[;&|\n])\s*" + pattern + r"(?=\s|$)", value)
    ] or ["unclassified"]


def summarize(messages):
    if not isinstance(messages, list):
        return {"schema_version": 1, "capture_status": "unsupported_format"}
    result = None
    calls = Counter()
    for item in messages:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "result":
            result = item
        message = item.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    calls[tool_name(block.get("name"))] += 1
    report = {
        "schema_version": 1,
        "capture_status": "captured" if result is not None else "no_result",
        "tool_calls": dict(sorted(calls.items())),
    }
    if result is None:
        return report
    subtype = result.get("subtype")
    report["result_subtype"] = (
        subtype if isinstance(subtype, str) and subtype in RESULT_TYPES else "other"
    )
    if isinstance(result.get("is_error"), bool):
        report["is_error"] = result["is_error"]
    for field in ("num_turns", "duration_ms"):
        value = result.get(field)
        if type(value) is int and 0 <= value <= 1_000_000_000:
            report[field] = value
    raw_denials = result.get("permission_denials")
    if not isinstance(raw_denials, list):
        report["denial_details_status"] = "unavailable"
        return report
    report["permission_denials_count"] = len(raw_denials)
    report["denial_details_status"] = "available"
    denials = []
    for denial in raw_denials[:200]:
        denial = denial if isinstance(denial, dict) else {}
        name = tool_name(denial.get("tool_name"))
        entry = {"tool": name}
        if name == "Bash":
            inputs = denial.get("tool_input")
            command = inputs.get("command") if isinstance(inputs, dict) else None
            entry["command_categories"] = command_categories(command)
        denials.append(entry)
    report["permission_denials"] = denials
    report["denials_truncated"] = len(raw_denials) > 200
    return report


def read_report(path):
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            return {"schema_version": 1, "capture_status": "input_too_large"}
        return summarize(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        status = "file_missing"
    except (ValueError, UnicodeError, RecursionError):
        status = "invalid_json"
    except OSError:
        status = "read_failed"
    # Never emit exception text: it can contain paths or input fragments.
    return {"schema_version": 1, "capture_status": status}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    report = read_report(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report.get("permission_denials_count", 0):
        print("::warning::Claude reported denied tool calls; inspect the sanitized diagnostic artifact.")
    if report["capture_status"] != "captured":
        print("::warning::Detailed Claude diagnostics unavailable; inspect capture_status in the artifact.")


if __name__ == "__main__":
    main()
