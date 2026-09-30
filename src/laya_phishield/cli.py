"""Batch CLI: scan mbox/eml/jsonl files for phishing.

    laya-phishield scan inbox.mbox more.eml --json

The laya agent and the trained head load lazily on the first scan, so
`--help` stays instant and importing this module never touches torch.
Both are injectable for tests.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import IO, List, Optional

if sys.version_info >= (3, 8):
    from importlib.metadata import version as _version
else:  # pragma: no cover
    def _version(_name):
        return "0.0.0"

from .pipeline import load_head, scan_email

__all__ = ["main", "read_emails"]


def read_emails(path: str) -> List[str]:
    """Raw emails from one .eml, .mbox or .jsonl file."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        if path.endswith(".jsonl"):
            return [json.loads(line)["raw"] for line in fh if line.strip()]
        if path.endswith(".mbox"):
            return _split_mbox(fh.read())
        return [fh.read()]


def _split_mbox(text: str) -> List[str]:
    """Split an mbox on its 'From ' delimiter lines (raw text, no re-parse)."""
    messages: List[str] = []
    chunk: List[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith("From ") and chunk:
            messages.append("".join(chunk).strip() + "\n")
            chunk = []
            continue
        chunk.append(line)
    if chunk:
        messages.append("".join(chunk).strip() + "\n")
    return messages


def _default_agent():
    import laya

    return laya.Agent()


def _emit(out: IO, verdict, source: str, as_json: bool) -> None:
    if as_json:
        payload = verdict.to_dict()
        payload["source"] = source
        out.write(json.dumps(payload) + "\n")
        return
    top = ", ".join("%s %.2f" % (name, value) for name, value in verdict.reasons[:2])
    flags = ("; flags: " + ", ".join(verdict.flags)) if verdict.flags else ""
    out.write("%-9s %.3f  %s  [%s]%s\n"
              % (verdict.label.upper(), verdict.score, source, top or "-", flags))


def main(argv: Optional[List[str]] = None, agent=None, head=None,
         out: Optional[IO] = None) -> int:
    out = out or sys.stdout
    parser = argparse.ArgumentParser(
        prog="laya-phishield", description="Explainable phishing detection.")
    parser.add_argument("--version", action="version",
                        version=_version("laya-phishield"))
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan mbox/eml/jsonl files")
    scan.add_argument("files", nargs="+", help="mbox, eml or jsonl files")
    scan.add_argument("--json", action="store_true",
                      help="one JSON verdict object per line")
    scan.add_argument("--limit", type=int, default=None,
                      help="scan at most N emails (after dedup by file order)")

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.error("unknown command %r" % args.command)

    emails: List[str] = []
    for path in args.files:
        try:
            emails.extend(read_emails(path))
        except OSError as exc:
            print("cannot read %s: %s" % (path, exc), file=sys.stderr)
            return 2
    if args.limit is not None:
        emails = emails[: args.limit]
    if not emails:
        print("no emails found", file=sys.stderr)
        return 2

    agent = agent or _default_agent()
    head = head or load_head()

    phish_count = 0
    for i, raw in enumerate(emails):
        verdict = scan_email(agent, head, raw)
        phish_count += verdict.label == "phishing"
        base = args.files[0] if len(args.files) == 1 else "batch"
        _emit(out, verdict, source="%s#%d" % (base, i + 1), as_json=args.json)

    if not args.json:
        out.write("%d email%s scanned, %d flagged\n"
                  % (len(emails), "" if len(emails) == 1 else "s", phish_count))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
