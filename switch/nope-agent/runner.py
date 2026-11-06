#!/usr/bin/env python3
"""Switch room agent runner for NOPE Never-Again Compiler.

Connects to Switch room events or operates in local interactive thread mode.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Add project root to sys.path so nope_core can be imported
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "core" / "src"))

from nope_core.agent import SwitchAgentDispatcher


def main() -> None:
    parser = argparse.ArgumentParser(description="NOPE Switch Room Agent Runner")
    parser.add_argument("--base-url", default=os.getenv("NOPE_BASE_URL", "http://localhost:8010"))
    parser.add_argument("--thread-id", default="switch-thread-demo")
    parser.add_argument("--user-id", default=os.getenv("USER", "engineer@acme.com"))
    args = parser.parse_args()

    dispatcher = SwitchAgentDispatcher(base_url=args.base_url)
    print(f"NOPE Switch Agent initialized (base: {args.base_url}, thread: {args.thread_id})")
    print("Type your message (e.g. '@nope teach We had INC-014: leaked auth tokens. Never log credentials.')")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            line = input(f"{args.user_id}> ")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        line = line.strip()
        if not line:
            continue
        if line.lower() in {"exit", "quit"}:
            break

        response = dispatcher.handle_message(args.thread_id, args.user_id, line)
        print(f"\n@nope:\n{response}\n")


if __name__ == "__main__":
    main()

