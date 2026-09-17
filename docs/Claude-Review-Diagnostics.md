# Claude review diagnostics

The Claude review workflow saves a sanitized diagnostic artifact for each run.
On the workflow run page, open **Artifacts** and download
**claude-review-diagnostics-RUN_ID-ATTEMPT**. Its summary.json contains the
completion status, counts of requested tools, and denied tool names. Bash
denials include only recognized command categories, with all arguments omitted.

A successful action exit is not proof that a final review was posted. Compare
the diagnostic result with the PR's review/progress comment. Permission denials
produce a workflow warning; they do not independently prove that every denied
call was necessary or that review publication failed.

The source file lives in the temporary GitHub runner and disappears with that
runner unless preserved. This workflow deliberately does not upload that raw
file. The extractor emits only constant labels and validated numbers/booleans:
no prompts, assistant text, file contents, paths, tool arguments, tokens, or
exception details. Unknown tool names become other. Unrecognized Bash commands
become unclassified; categories are diagnostic hints, not a shell parser.
At most 200 denial entries are included, with the full count and a truncation flag.

The capture step runs even when the Claude action fails. It uses the action's
execution_file output or the known runner-temporary fallback. Missing, invalid,
oversized, or incomplete output produces an explicit capture_status instead of
publishing raw data. Force-cancelled jobs may not get to run their cleanup steps.

The artifact is retained for seven days. Full execution output stays disabled.
The workflow does not broaden Claude's tool permissions to collect diagnostics.
A later retry runs against the workflow available to that run; pushing this
workflow change to an open PR triggers a fresh review with capture enabled.
Re-running an older workflow alone does not add these steps.

Local verification:

~~~text
python scripts/test_claude_review_diagnostics.py
~~~
