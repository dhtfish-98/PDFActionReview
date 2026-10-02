import argparse
import json

from . import __version__
from .review import review_pdf


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only local raw PDF lexical name review; keywords are observations, not actions or malware.")
    parser.add_argument("pdf", help="One explicitly named local regular raw PDF file")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    report = review_pdf(args.pdf)
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
