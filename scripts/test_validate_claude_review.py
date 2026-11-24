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
SUCCESS = {
    "capture_status": "captured",
    "result_subtype": "success",
    "is_error": False,
    "tool_calls": {"mcp__github_comment__update_claude_comment": 1},
}


def comment(body, author="claude"):
    return {"user": {"login": author}, "body": body}


class ReviewCompletionTests(unittest.TestCase):
    def test_current_final_summary_in_paginated_response_passes(self):
        comments = [[comment("Old progress")], [comment("No issues found.\n" + MARKER)]]
        self.assertIsNone(completion_error(SUCCESS, comments, MARKER))

    def test_exact_marker_does_not_require_comment_tool_diagnostics(self):
        report = {key: value for key, value in SUCCESS.items() if key != "tool_calls"}
        self.assertIsNone(completion_error(
            report, [comment("No issues found.\n" + MARKER)], MARKER))

    def test_successful_exit_with_only_progress_is_incomplete(self):
        report = {**SUCCESS, "permission_denials_count": 3}
        self.assertIsNotNone(completion_error(report, [comment("Still reviewing")], MARKER))

    def test_action_finished_summary_for_exact_run_and_head_passes_without_marker(self):
        body = (
            "**Claude finished @actuarius-bot[bot]'s task in 1m 6s** —— "
            "[View job](https://github.com/DigitumDei/agentpalace/actions/runs/123)\n\n"
            "---\n### Review: PR #169\n\n### Summary\n\n"
            "The requested repair is present and correct. No new findings were identified.\n\n"
            f"Reviewed commit: `{HEAD}`."
        )
        self.assertIsNone(completion_error(SUCCESS, [comment(body, "claude[bot]")], MARKER))

    def test_action_finished_summary_with_abbreviated_head_passes_without_marker(self):
        # The shape published on PR 196: no marker, and only the short SHA.
        head = "6dcf40c20150636f90adddb70696512e809df6d6"
        marker = f"<!-- agentpalace-claude-review:45333520029:1:{head}:completed -->"
        body = (
            "**Claude finished @DigitumDei's task in 13s** —— "
            "[View job](https://github.com/DigitumDei/agentpalace/actions/runs/45333520029)\n\n"
            "---\n### Review of PR #196 at 6dcf40c\n\n**No issues found.**\n\n"
            "- **Retry loop:** It makes up to 4 attempts and waits between them.\n"
            "- **Scope:** Only the Windows step changes.\n\n"
            "**Validation limits:** I reviewed the diff only and ran no builds or tests."
        )
        self.assertIsNone(completion_error(SUCCESS, [comment(body, "claude[bot]")], marker))

    def test_abbreviated_commit_must_be_a_whole_token_prefixing_the_head(self):
        head = "6dcf40c20150636f90adddb70696512e809df6d6"
        marker = f"<!-- agentpalace-claude-review:123:1:{head}:completed -->"
        template = (
            "**Claude finished @bot's task** —— "
            "[View job](https://github.com/org/repo/actions/runs/123)\n\n"
            "---\n### Review at {cited}\n\n"
            + "No findings. The review is complete with sufficient detail." * 3
        )
        for cited, passes in [
            ("6dcf40c", True),
            ("6dcf40c20150", True),
            (head, True),
            ("6dcf40", False),            # shorter than git's default abbreviation
            ("6dcf40d", False),           # another commit
            ("dcf40c2", False),           # inside the head, but not a prefix
            ("6dcf40cffff", False),       # shares seven characters, then diverges
            ("a6dcf40c", False),          # the prefix buried in a longer token
            (head + "0", False),          # longer than a SHA
            ("6DCF40C", False),           # git prints lower case
        ]:
            with self.subTest(cited=cited):
                error = completion_error(
                    SUCCESS, [comment(template.format(cited=cited))], marker)
                self.assertEqual(error is None, passes)

    def test_generated_fallback_is_scoped_and_rejects_progress(self):
        template = (
            "**Claude finished @bot's task** —— "
            "[View job](https://github.com/org/repo/actions/runs/{run})\n\n"
            "---\n### Review\n\n{content}\n\nReviewed commit: `{head}`."
        )
        cases = [
            (template.format(
                run=122,
                head=HEAD,
                content="No findings. The review is complete with sufficient detail." * 3,
            ), "claude", SUCCESS),
            (template.format(
                run=123,
                head="b" * 40,
                content="No findings. The review is complete with sufficient detail." * 3,
            ), "claude", SUCCESS),
            (template.format(
                run=123,
                head=HEAD,
                content="- [ ] Still reviewing the changed implementation." * 5,
            ), "claude", SUCCESS),
            (template.format(
                run=123,
                head=HEAD,
                content="No findings. The review is complete with sufficient detail." * 3,
            ), "contributor", SUCCESS),
            (template.format(
                run=123,
                head=HEAD,
                content="No findings. The review is complete with sufficient detail." * 3,
            ), "claude", {**SUCCESS, "tool_calls": {}}),
        ]
        for body, author, report in cases:
            with self.subTest(author=author, report=report, body=body):
                self.assertIsNotNone(completion_error(report, [comment(body, author)], MARKER))

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
