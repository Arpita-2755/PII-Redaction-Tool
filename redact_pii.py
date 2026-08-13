"""Command-line entrypoint for redacting PII from DOCX files."""

from __future__ import annotations

import argparse
from pathlib import Path
import tempfile

from pii_redaction import redact_docx
from pii_redaction.evaluation import write_docx_report, write_markdown_report
from pii_redaction.gold_fixture import run_gold_fixture


def main() -> None:
    parser = argparse.ArgumentParser(description="Redact PII from a DOCX file.")
    parser.add_argument("input", help="Path to the input DOCX file")
    parser.add_argument(
        "--output",
        "-o",
        default="outputs/redacted_output.docx",
        help="Path for the redacted DOCX file",
    )
    parser.add_argument(
        "--report-json",
        default="outputs/redaction_run.json",
        help="Path for the JSON run report",
    )
    parser.add_argument(
        "--report-md",
        default="outputs/evaluation_report.md",
        help="Path for the Markdown evaluation report",
    )
    parser.add_argument(
        "--report-docx",
        default="outputs/evaluation_report.docx",
        help="Path for the DOCX evaluation report",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as fixture_tmp:
        gold_score, _ = run_gold_fixture(Path(fixture_tmp))
    run_report = redact_docx(args.input, args.output, args.report_json)
    write_markdown_report(run_report, args.report_md, gold_score)
    write_docx_report(args.report_md, args.report_docx)

    print(f"Redacted DOCX: {Path(args.output).resolve()}")
    print(f"Evaluation report: {Path(args.report_docx).resolve()}")
    print(f"Total replacements: {run_report['total_replacements']}")
    print(f"Counts by type: {run_report['counts_by_type']}")


if __name__ == "__main__":
    main()
