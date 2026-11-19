"""Command-line entry point for the local audit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory

from . import VERSION
from .gpo import CATALOG_VERSION, load_xml, parse_gpo
from .inheritance import parse_inheritance
from .report import render
from .rsop import parse_rsop

FILE_LIMIT = 16 * 1024 * 1024
IMPORT_LIMIT = 64 * 1024 * 1024


def _audit(args):
    result = {"schema_version": 1, "tool_version": VERSION, "catalog_version": CATALOG_VERSION,
              "inputs": [], "gpos": [], "findings": [], "inheritance": [], "observations": [],
              "coverage": {}, "comparison": {"minimum_password_length": args.min_password_length,
                                             "maximum_screen_saver_seconds": args.max_screen_saver_seconds}}
    remaining = IMPORT_LIMIT
    for kind in ("gpo", "inheritance", "rsop"):
        for path in sorted(set(getattr(args, kind)), key=str):
            source = str(path)
            item = {"type": kind, "source": source, "sha256": None, "status": "Rejected"}
            try:
                if not stat.S_ISREG(path.stat().st_mode):
                    raise ValueError("Input must be a regular file")
                with path.open("rb") as handle:
                    size = os.fstat(handle.fileno()).st_size
                    if size > FILE_LIMIT:
                        raise ValueError("Input exceeds the 16 MiB file limit")
                    if size > remaining:
                        raise ValueError("Import exceeds the 64 MiB total limit")
                    data = handle.read(min(FILE_LIMIT, remaining) + 1)
                remaining -= len(data)
                if len(data) > FILE_LIMIT or remaining < 0:
                    raise ValueError("Input exceeded the import limits while reading")
                digest = item["sha256"] = hashlib.sha256(data).hexdigest()
                if kind == "inheritance":
                    result["inheritance"].append(parse_inheritance(data, source, digest))
                elif kind == "rsop":
                    result["observations"].extend(parse_rsop(load_xml(data), source, digest))
                else:
                    parsed = parse_gpo(load_xml(data), source, digest)
                    result["gpos"].extend(parsed["gpos"])
                    result["findings"].extend(parsed["findings"])
                item["status"] = "Read"
            except (OSError, ValueError) as exc:
                item["reason"] = str(exc)
            result["inputs"].append(item)
    for kind, key, completed, missing in (
        ("gpo", "declarations", bool(result["gpos"]), "No readable GPO declaration report."),
        ("inheritance", "ou_precedence", bool(result["inheritance"]), "No readable inheritance snapshot."),
        ("rsop", "effective_settings", any(r["status"] == "Observed" for r in result["observations"]),
         "No target-specific logged setting value was established."),
    ):
        rejected = sum(r["status"] == "Rejected" for r in result["inputs"] if r["type"] == kind)
        result["coverage"][key] = {"status": "Evidence available" if completed else "Not assessed",
                                   "reason": None if completed else missing, "rejected_files": rejected}
    for row in result["findings"] + result["observations"]:
        _compare(row, args)
    return result


def _compare(row, args):
    password = row["policy_id"] == "minimum-password-length"
    threshold = args.min_password_length if password else args.max_screen_saver_seconds
    if threshold is None:
        return
    comparison = {"threshold": threshold, "outcome": "Not assessed"}
    row["comparison"] = comparison
    if row["status"] not in ("Declared", "Observed") or row.get("state") == "Disabled":
        return
    if row["status"] == "Declared" and row.get("section_enabled") is not True:
        return
    value = row.get("value")
    if type(value) is int:
        matches = value >= threshold if password else 0 < value <= threshold
        comparison["outcome"] = "Meets threshold" if matches else "Outside threshold"


def _write(output, result):
    # Stage the pair first. Exclusive directory creation reserves the requested
    # name even on platforms where rename can replace another empty directory.
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".grits-", dir=output.parent) as stage:
        stage = Path(stage)
        (stage / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        (stage / "report.html").write_text(render(result), encoding="utf-8", errors="backslashreplace")
        output.mkdir(mode=0o700)
        installed = []
        try:
            for name in ("report.json", "report.html"):
                destination = output / name
                (stage / name).replace(destination)
                installed.append(destination)
        except OSError:
            for destination in installed:
                destination.unlink()
            output.rmdir()
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(prog="grits", description="Review exported on-premises Group Policy evidence offline.")
    parser.add_argument("--version", action="version", version="GPO Grits " + VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit", help="Write an HTML and JSON report from local evidence.")
    for key, description in (("gpo", "Get-GPOReport XML"), ("inheritance", "saved Get-GPInheritance JSON"),
                              ("rsop", "RSoP logging XML")):
        audit.add_argument("--" + key, nargs="+", action="extend", default=[], type=Path, metavar="FILE",
                           help=description + " file(s)")
    audit.add_argument("--out", type=Path, required=True, help="new directory for report.html and report.json")
    audit.add_argument("--min-password-length", type=int, metavar="CHARACTERS", help="optional local lower threshold")
    audit.add_argument("--max-screen-saver-seconds", type=int, metavar="SECONDS", help="optional local upper threshold")
    args = parser.parse_args(argv)
    if not (args.gpo or args.inheritance or args.rsop):
        parser.error("supply at least one --gpo, --inheritance or --rsop file")
    if args.min_password_length is not None and args.min_password_length < 0:
        parser.error("--min-password-length must be nonnegative")
    if args.max_screen_saver_seconds is not None and args.max_screen_saver_seconds < 1:
        parser.error("--max-screen-saver-seconds must be positive")
    if args.out.exists():
        parser.error("--out already exists; choose a new report directory")
    result = _audit(args)
    try:
        _write(args.out, result)
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        return 2
    rejected = [i for i in result["inputs"] if i["status"] == "Rejected"]
    print(f"{len(result['gpos'])} GPOs, {len(rejected)} rejected inputs. Open {args.out / 'report.html'}")
    for item in rejected:
        print(f"{item['source']}: {item['reason']}", file=sys.stderr)
    return 1 if rejected else 0
