import argparse
import json

from . import __version__
from .review import Limits, Review, review_pdf


class ArgumentsOpen(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentsOpen


def main(argv=None) -> int:
    parser = Parser(description="Read-only local raw PDF lexical name review; keywords are observations, not actions or malware.", allow_abbrev=False)
    parser.add_argument("pdf", help="One explicitly named local regular raw PDF file")
    parser.add_argument("--version", action="version", version=__version__)
    try:
        args = parser.parse_args(argv)
        report = review_pdf(args.pdf)
    except ArgumentsOpen:
        review = Review(Limits())
        review.add("OPEN", "invalid_arguments", None,
                   "Command arguments are unsupported or incomplete; no input was reviewed.", incomplete=True)
        report = review.finish()
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
