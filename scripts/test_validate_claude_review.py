"""Regression tests for successful exits that did not publish a final review."""

import json
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("validate-claude-review.py")
completion_error = runpy.run_path(str(SCRIPT))["completion_error"]
HEAD = "a" * 40
MARKER = f"<!-- agentpalace-claude-review:123:1:{HEAD}:completed -->"
SUCCESS = {"capture_status": "captured", "result_subtype": "success", "is_error": False}


def comment(body, author="claude"):
    return {"user": {"login": author}, "body": body}


class ReviewCompletionTests(unittest.TestCase):
    def test_current_final_summary_in_paginated_response_passes(self):
        comments = [[comment("Old progress")], [comment("No issues found.\n" + MARKER)]]
        self.assertIsNone(completion_error(SUCCESS, comments, MARKER))

    def test_successful_exit_with_only_progress_is_incomplete(self):
        report = {**SUCCESS, "permission_denials_count": 3}
        self.assertIsNotNone(completion_error(report, [comment("Still reviewing")], MARKER))

    def test_old_run_attempt_head_or_other_author_cannot_satisfy_gate(self):
        for body, author in [
            (MARKER.replace(":123:", ":122:"), "claude"),
            (MARKER.replace(":1:", ":2:"), "claude"),
            (MARKER.replace(HEAD, "b" * 40), "claude"),
            (MARKER, "contributor"),
        ]:
            with self.subTest(body=body, author=author):
                self.assertIsNotNone(completion_error(
                    SUCCESS, [comment("No issues found.\n" + body, author)], MARKER))

    def test_marker_without_any_summary_is_incomplete(self):
        self.assertIsNotNone(completion_error(SUCCESS, [comment(MARKER)], MARKER))

    def test_failed_or_missing_execution_cannot_pass_with_a_comment(self):
        for report in [None, {}, {"capture_status": "file_missing"},
                       {**SUCCESS, "is_error": True},
                       {**SUCCESS, "result_subtype": "error_max_turns"}]:
            with self.subTest(report=report):
                self.assertIsNotNone(completion_error(
                    report, [comment("No issues found.\n" + MARKER)], MARKER))

    def test_recovered_permission_denial_does_not_invalidate_final_review(self):
        report = {**SUCCESS, "permission_denials_count": 1}
        self.assertIsNone(completion_error(
            report, [comment("Review complete using Read instead.\n" + MARKER)], MARKER))

    def test_malformed_comments_and_marker_fail_safely(self):
        for comments in [None, {}, [None, {"user": []}, {"user": {"login": []}, "body": MARKER}]]:
            self.assertIsNotNone(completion_error(SUCCESS, comments, MARKER))
        self.assertIsNotNone(completion_error(SUCCESS, [], "PRIVATE_SENTINEL"))

    def test_cli_exits_nonzero_without_echoing_malformed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.json"
            comments = Path(directory) / "comments.json"
            summary.write_text("PRIVATE_SENTINEL", encoding="utf-8")
            comments.write_text(json.dumps([]), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(summary), str(comments), MARKER],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("::error::", result.stdout)
            self.assertNotIn("PRIVATE_SENTINEL", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
