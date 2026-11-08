"""Validate scanner output before it can be used as passing evidence."""

from __future__ import annotations

from typing import Any


def checked_report(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Semgrep report must be an object")
    for key in ("results", "errors"):
        if not isinstance(payload.get(key), list) or any(not isinstance(item, dict) for item in payload[key]):
            raise ValueError(f"Semgrep report requires a list of objects in {key}")
    for finding in payload["results"]:
        if not isinstance(finding.get("path"), str):
            raise ValueError("Semgrep finding requires a file path")
        for key in ("start", "extra"):
            if key in finding and not isinstance(finding[key], dict):
                raise ValueError(f"Semgrep finding {key} must be an object")
        for key in ("line", "col"):
            location = finding.get("start", {})
            if key in location and (type(location[key]) is not int or location[key] < 1):
                raise ValueError(f"Semgrep finding {key} must be a positive integer")
        extra = finding.get("extra", {})
        if "metadata" in extra and not isinstance(extra["metadata"], dict):
            raise ValueError("Semgrep finding metadata must be an object")
    if "paths" in payload:
        paths = payload["paths"]
        if (not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list)
                or any(not isinstance(path, str) for path in paths["scanned"])):
            raise ValueError("Semgrep scanned paths must be a list of file paths")
    return payload
