"""Regression tests for publishing only allowlisted review diagnostics."""

import json
import runpy
import tempfile
import unittest
from pathlib import Path

MODULE = runpy.run_path(str(Path(__file__).with_name("claude-review-diagnostics.py")))
summarize = MODULE["summarize"]
read_report = MODULE["read_report"]


class ReviewDiagnosticsTests(unittest.TestCase):
    def test_denied_tools_are_useful_without_publishing_arguments(self):
        secret = "PRIVATE_SENTINEL_DO_NOT_PUBLISH"
        result = summarize([
            {"type": "assistant", "message": {"content": [
                {"type": "text", "text": secret},
                {"type": "tool_use", "name": "Read", "input": {"path": secret}},
                {"type": "tool_use", "name": secret},
            ]}},
            {"type": "result", "subtype": "success", "is_error": False,
             "result": secret, "errors": [secret], "session_id": secret,
             "num_turns": 25, "duration_ms": 71921,
             "permission_denials": [
                 {"tool_name": "Bash", "tool_input": {
                     "command": "gh api repos/private/private -H 'Authorization: " + secret + "'",
                     "description": secret}},
                 {"tool_name": "Bash", "tool_input": {
                     "command": "cd " + secret + " && git show HEAD:" + secret + " | sed -n '1p'"}},
                 {"tool_name": "Read", "tool_input": {"file_path": secret}},
                 {"tool_name": secret, "tool_input": {"command": secret}},
             ]},
        ])
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["permission_denials_count"], 4)
        self.assertEqual(result["permission_denials"][0]["command_categories"], ["gh api"])
        self.assertEqual(set(result["permission_denials"][1]["command_categories"]),
                         {"cd", "git show", "sed"})
        self.assertEqual(result["permission_denials"][2], {"tool": "Read"})
        self.assertEqual(result["permission_denials"][3], {"tool": "other"})
        self.assertEqual(result["tool_calls"], {"Read": 1, "other": 1})


    def test_cli_writes_only_summary_and_safe_console_output(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "execution.json"
            target = Path(directory) / "artifact" / "summary.json"
            source.write_text(json.dumps([{
                "type": "result", "subtype": "success", "result": "PRIVATE_SENTINEL",
                "permission_denials": [{
                    "tool_name": "Bash",
                    "tool_input": {"command": "gh pr review --body PRIVATE_SENTINEL"},
                }],
            }]), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("claude-review-diagnostics.py")),
                 str(source), str(target)],
                capture_output=True, text=True, check=True,
            )
            self.assertNotIn("PRIVATE_SENTINEL", completed.stdout + completed.stderr)
            self.assertNotIn("PRIVATE_SENTINEL", target.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(target.read_text(encoding="utf-8"))
                             ["permission_denials"][0]["command_categories"], ["gh pr review"])
            self.assertIn("::warning::", completed.stdout)

    def test_malformed_fields_never_echo_untrusted_values(self):
        result = summarize([{"type": "result", "subtype": {"secret": "sentinel"},
                             "is_error": "sentinel", "num_turns": "sentinel",
                             "permission_denials": [None, {"tool_name": ["sentinel"]}]}])
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertEqual(result["result_subtype"], "other")

    def test_missing_and_invalid_files_do_not_publish_raw_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-name.json"
            self.assertEqual(read_report(path)["capture_status"], "file_missing")
            path.write_text("PRIVATE_SENTINEL_INVALID_JSON", encoding="utf-8")
            self.assertEqual(read_report(path),
                             {"schema_version": 1, "capture_status": "invalid_json"})

    def test_absent_results_and_unsupported_format_are_explicit(self):
        self.assertEqual(summarize([])["capture_status"], "no_result")
        self.assertEqual(summarize({"private": "sentinel"})["capture_status"],
                         "unsupported_format")
        self.assertEqual(summarize([{"type": "result"}])["denial_details_status"],
                         "unavailable")

    def test_empty_denials_and_bounded_large_reports(self):
        self.assertEqual(summarize([{"type": "result", "permission_denials": []}])
                         ["permission_denials_count"], 0)
        report = summarize([{"type": "result", "permission_denials": [{}] * 205}])
        self.assertEqual(report["permission_denials_count"], 205)
        self.assertEqual(len(report["permission_denials"]), 200)
        self.assertTrue(report["denials_truncated"])


if __name__ == "__main__":
    unittest.main()
