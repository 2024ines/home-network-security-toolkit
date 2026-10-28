#!/usr/bin/env python3
"""Launcher:  python run.py            -> opens the dashboard
              python run.py --demo     -> dashboard with simulated data
              python run.py scan --i-am-authorised
"""
import sys
from hnst.cli import main

if __name__ == "__main__":
    sys.exit(main())