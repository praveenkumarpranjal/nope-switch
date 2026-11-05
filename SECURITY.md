# Security policy

If you discover a vulnerability in NOPE or this repository:

1. Do not disclose exploit details publicly.
2. Open a private security advisory on the hosting repository, or email the maintainers listed there.
3. Include reproduction steps, impacted endpoint/file, and a proposed mitigation if known.
4. Allow at least 72 hours for acknowledgment and a mutually agreed disclosure schedule.

NOPE's security model assumes:

- API keys and GitHub tokens are supplied out of band.
- Never commit production samples, customer identifiers or unredacted incident reports.
- Bugs that could activate or weaken a rule are treated as high severity.
- Bugs in activation/approval are stop-ship defects, even if they are outside the usual request/response path.

Credit is available after remediation unless you prefer to remain anonymous.
