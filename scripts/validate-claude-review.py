#!/usr/bin/env python3
"""Check sanitized SDK status and a final comment for this run, attempt, and head."""

import argparse
import json
import re
from pathlib import Path

MAX_INPUT_BYTES = 64 * 1024 * 1024
MARKER_PATTERN = (
    r"<!-- agentpalace-claude-review:(?P<run_id>[0-9]+):"
    r"(?P<attempt>[0-9]+):(?P<head>[a-f0-9]{40}):completed -->"
)
REVIEW_AUTHORS = frozenset({"claude", "claude[bot]"})
FINISHED_COMMENT_PATTERN = re.compile(
    r"\A\*\*Claude finished [^\r\n]+\*\*[^\r\n]*"
    r"\[View job\]\(https://github\.com/[^/\s)]+/[^/\s)]+/actions/runs/"
    r"(?P<run_id>[0-9]+)(?:[/?#][^\s)]*)?\)\r?\n\r?\n---\r?\n"
)
FINAL_HEADING_PATTERN = re.compile(
    r"^#{1,6}\s+(?:summary|findings|review|result|conclusion)\b",
    re.IGNORECASE | re.MULTILINE,
)
UNCHECKED_ITEM_PATTERN = re.compile(r"^\s*[-*]\s+\[\s\]", re.MULTILINE)


def generated_final_summary(report, body, marker_match):
    """Return whether the action published a complete summary without the prompt marker."""
    tool_calls = report.get("tool_calls")
    if not isinstance(tool_calls, dict):
        return False
    update_count = tool_calls.get("mcp__github_comment__update_claude_comment")
    if type(update_count) is not int or update_count < 1:
        return False

    finished = FINISHED_COMMENT_PATTERN.match(body)
    if finished is None or finished.group("run_id") != marker_match.group("run_id"):
        return False
    summary = body[finished.end():].strip()
    if len(summary) < 120 or UNCHECKED_ITEM_PATTERN.search(summary):
        return False
    head = marker_match.group("head")
    if re.search(rf"(?<![a-f0-9]){re.escape(head)}(?![a-f0-9])", summary) is None:
        return False
    return FINAL_HEADING_PATTERN.search(summary) is not None


def completion_error(report, comments, marker):
    """Return a fixed error message, or None when a completed review was posted."""
    marker_match = re.fullmatch(MARKER_PATTERN, marker) if isinstance(marker, str) else None
    if marker_match is None:
        return "Invalid review completion marker."
    if not isinstance(report, dict) or report.get("capture_status") != "captured":
        return "Review execution diagnostics are unavailable."
    if report.get("result_subtype") != "success" or report.get("is_error") is not False:
        return "Claude did not finish execution successfully."
    if not isinstance(comments, list):
        return "Posted review comments are unavailable."

    # gh api --paginate --slurp returns an array of page arrays.
    for page in comments:
        for comment in page if isinstance(page, list) else [page]:
            if not isinstance(comment, dict):
                continue
            user = comment.get("user")
            body = comment.get("body")
            if not isinstance(user, dict) or not isinstance(body, str):
                continue
            login = user.get("login")
            if not isinstance(login, str) or login not in REVIEW_AUTHORS:
                continue
            if marker in body and body.replace(marker, "").strip():
                return None
            if generated_final_summary(report, body, marker_match):
                return None
    return "Claude did not publish a final review summary for this run and commit."


def read_json(path):
    """Read bounded JSON without echoing input or exception details."""
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("Input too large")
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    parser.add_argument("comments", type=Path)
    parser.add_argument("marker")
    args = parser.parse_args()
    try:
        error = completion_error(read_json(args.summary), read_json(args.comments), args.marker)
    except (OSError, ValueError, UnicodeError, RecursionError):
        error = "Review completion inputs are missing, invalid, or too large."
    if error:
        print("::error::" + error)
        return 1
    print("Claude review completion verified for the current run and commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
