#!/usr/bin/env python3
import sys
import asyncio
from main import run_audit

if __name__ == "__main__":
    try:
        asyncio.run(run_audit())
    except KeyboardInterrupt:
        sys.exit(0)
