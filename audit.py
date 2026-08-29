#!/usr/bin/env python
"""Convenience entry point: `python audit.py --profile myprofile`."""
import sys

# Windows' console codepage isn't UTF-8 by default, so any plain print() of
# non-ASCII (em dashes, arrows) mangles on stderr/stdout unless reconfigured
# — the rich console report never hit this because rich forces UTF-8
# internally, but plain print() calls (warnings, --history-file output) do.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from aws_security_audit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
