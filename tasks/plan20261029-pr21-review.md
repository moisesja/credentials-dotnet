# PR #21 review plan

Owner intent: review the newly opened PR critically and post a specific review comment or a brief approving comment on GitHub.

Decisions: review head 2335ef741eab5a10508f41bcaaad5543a1bea59a against d06943c2ea7f0f11876cb373dd4ca1d86b5d3cb8. This is a review, not an implementation task. Source, tests, PRD, and release documentation will not be edited. The user explicitly authorized posting the review. Any proposed code fix requires a separate approved implementation plan.

- [x] Read title, description, complete diff, commits, and existing review discussion.
- [x] Independently examine schema isolation and proof/dependency behavior, including adversarial analysis.
- [x] Run existing tests and inspect CI; reproduce actionable concerns in scratch space.
- [x] Check the PR head has not changed and post evidence-backed findings or approval.

## Review results

Posted: https://github.com/moisesja/credentials-dotnet/pull/21#issuecomment-6513682713

- Local tests: 418 passed; W3C harness skipped because its external suite was not configured locally.
- GitHub ordinary CI, API compatibility, API coverage and closure checks passed. W3C job 123858993882 failed with 54 passing / 5 failing, below baseline 57.
- Blocking concern: DataProofs 1.5.0 intentionally rejects direction-bearing language values; this breaks four W3C cases and leaves the conformance documentation stale. Differential scratch probe confirmed old canonical bytes omit direction, so bypassing the new guard is unsafe. Secure RDFC support belongs upstream; integration, coverage and accurate compatibility documentation belong here.
- Non-blocking concern: high-S KB/VP freshness tests need successful matching-expectation controls and assertions of the failure reason.
- Separate conditional schema-isolation findings were delivered privately outside the repository, following SECURITY.md. No vulnerability details were posted publicly.
- GitHub integration refused review/comment writes with HTTP 403; the authorized comment succeeded through the authenticated local gh CLI. Comment was fetched back and verified.
- No source, test, PRD, or CHANGELOG edits: this task reviews an unreleased PR and does not change product behavior. Implementation remediation requires a separately approved plan.
