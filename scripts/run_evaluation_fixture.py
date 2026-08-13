"""Run the controlled gold-label evaluation fixture."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pii_redaction.gold_fixture import run_gold_fixture
from pii_redaction.evaluation import score_gold_fixture, write_docx_report, write_markdown_report


def main() -> None:
    output_dir = ROOT / "outputs" / "fixture"
    score, run_report = run_gold_fixture(output_dir)
    write_markdown_report(run_report, output_dir / "fixture_evaluation.md", score)
    write_docx_report(output_dir / "fixture_evaluation.md", output_dir / "fixture_evaluation.docx")

    print(score)


if __name__ == "__main__":
    main()
