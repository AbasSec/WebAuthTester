#!/usr/bin/env python3
import sys
from main import run_audit
import asyncio
from main import get_args

if __name__ == "__main__":
    args = get_args()
    asyncio.run(run_audit(args))
