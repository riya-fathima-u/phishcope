"""Command line entry point:  python -m phishscope.cli suspicious.eml -o report.html"""
import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze
from .report import build_report


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phishscope", description="Triage a suspicious .eml file.")
    ap.add_argument("eml", help="path to the .eml file")
    ap.add_argument("-o", "--output", help="write an HTML report to this path")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = ap.parse_args(argv)

    path = Path(args.eml)
    if not path.is_file():
        ap.error(f"file not found: {path}")
    result = analyze(path.read_bytes(), path.name)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['verdict']}  (score {result['score']}/100)")
        for f in result["findings"]:
            print(f"  [{f['severity']:<6}] {f['title']}: {f['detail']}")
    if args.output:
        Path(args.output).write_text(build_report(result), encoding="utf-8")
        print(f"Report saved to {args.output}", file=sys.stderr)
    return 0 if result["score"] < 50 else 2   # non-zero exit for likely phishing (handy in scripts)


if __name__ == "__main__":
    sys.exit(main())
