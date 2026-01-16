#!/usr/bin/env python3
"""quick CLI wrapper for testing the parsers

usage:
  python run.py --file /var/log/auth.log --format authlog
  python run.py --file access.log --format apache --output results.json
"""

import argparse
import json
import sys

def main():
    parser = argparse.ArgumentParser(description="log analyzer prototype")
    parser.add_argument("--file", required=True, help="log file to parse")
    parser.add_argument("--format", required=True, 
                       choices=["syslog", "authlog", "apache", "windows"],
                       help="log format")
    parser.add_argument("--output", help="output file (json)")
    parser.add_argument("--threshold", type=int, default=5,
                       help="brute force threshold (default: 5)")
    args = parser.parse_args()
    
    # TODO: wire up the actual parsers and detectors
    # for now just print what we'd do
    print(f"would parse {args.file} as {args.format}")
    print(f"brute force threshold: {args.threshold}")
    if args.output:
        print(f"output to: {args.output}")
    else:
        print("output to: console")

if __name__ == "__main__":
    main()
