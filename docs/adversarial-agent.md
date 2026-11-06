# Independent adversarial challenge

Assign the challenger to a separate agent from the rule author. Give that agent the original incident, invariant, remediation and application logging context. When generating a fresh challenge, withhold the proposed rule and the author's fixtures so the agent creates its own interpretations and variants. The challenger should return named unsafe examples and safe negative controls before the reviewer runs the proposed rule.

The checked-in `demo-app/fixtures/adversarial-challenge.json` bundle contains offline examples authored by an independent agent. It is a reproducible challenge corpus, not evidence that a live agent ran during a CI check. The examples cover logging methods, bracket access, header case, nested payloads and API keys. Safe controls include explicit redaction and ordinary identifiers. The demo logger automatically redacts recognized metadata keys, so unsafe logger examples place credentials under neutral metadata keys that bypass that protection.

Run each example against the candidate rule. Count unsafe examples detected, unsafe examples missed and safe examples incorrectly detected. The reviewer should reject candidates that fail the configured detection and false-positive thresholds. Keep the examples and results with the Scar so later replacements must satisfy the same regression corpus. Add newly discovered bypasses as further tests; do not rewrite expected labels merely to improve a candidate's score.

The original lexical credential rule may miss mixed-case or uppercase header names, uppercase API keys and member-access variants. It may also flag safe literal redactions because it recognizes credential names without proving that a secret reaches the log. Those outcomes should remain visible in review.
