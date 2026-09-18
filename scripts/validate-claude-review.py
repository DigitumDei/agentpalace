#!/usr/bin/env python3
"""Check sanitized SDK status and a final comment for this run, attempt, and head."""

import argparse
import json
import re
from pathlib import Path

MAX_INPUT_BYTES = 64 * 1024 * 1024
MARKER_PATTERN = r"<!-- agentpalace-claude-review:[0-9]+:[0-9]+:[a-f0-9]{40}:completed -->"
REVIEW_AUTHORS = frozenset({"claude", "claude[bot]"})


def completion_error(report, comments, marker):
    """Return a fixed error message, or None when a completed review was posted."""
    if not isinstance(marker, str) or re.fullmatch(MARKER_PATTERN, marker) is None:
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
