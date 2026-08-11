#!/usr/bin/env python
"""Convenience entry point: `python audit.py --profile myprofile`."""
import sys

from aws_security_audit.cli import main

if __name__ == "__main__":
    sys.exit(main())
