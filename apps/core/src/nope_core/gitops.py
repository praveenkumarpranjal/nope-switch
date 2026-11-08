"""Read back the exact merged rule before the merge webhook can activate it."""

from __future__ import annotations

import base64
import hashlib
import os
import re

import httpx


class GitHubUnavailable(RuntimeError):
    pass


def verify_merged_rule(repository: str, commit: str, rule_sha256: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("GitHub verification requires an exact repository and merge commit")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=15, follow_redirects=False, headers=headers) as client:
            response = client.get(
                f"https://api.github.com/repos/{repository}/contents/config/.semgrep/nope-active.yml",
                params={"ref": commit},
            )
            response.raise_for_status()
            document = response.json()
    except (httpx.HTTPError, ValueError):
        raise GitHubUnavailable(
            "Cannot verify the merged rule on GitHub; configure GITHUB_TOKEN with repository contents read access and retry"
        ) from None
    if (not isinstance(document, dict) or document.get("type") != "file"
            or document.get("encoding") != "base64" or not isinstance(document.get("content"), str)):
        raise ValueError("GitHub did not return the merged safeguard file")
    try:
        raw = base64.b64decode("".join(document["content"].split()), validate=True)
    except ValueError as exc:
        raise ValueError("GitHub returned invalid merged rule content") from exc
    if hashlib.sha256(raw).hexdigest() != rule_sha256:
        raise ValueError("The rule in the merged commit differs from the exact approved rule hash")
