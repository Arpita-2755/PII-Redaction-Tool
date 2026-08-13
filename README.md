# PII Redaction Tool

A lightweight DOCX privacy tool that detects personally identifiable information (PII) and replaces it with realistic fake alternatives while preserving the document format as much as possible.

The project was built for the Scaler AI Labs PII Redaction Tool assignment. It processes the supplied Red Herring Prospectus DOCX and produces a redacted DOCX suitable for safer review or sharing.

## Key Capabilities

- Redacts PII from `.docx` files.
- Replaces sensitive values with fake alternatives instead of generic masks.
- Keeps repeated values consistent across the document. For example, the same original email always maps to the same fake email.
- Scans Word document body, headers, footers, footnotes, endnotes, and comments.
- Provides both a command-line script and a deployable web upload interface.
- Includes an evaluation report with defensible precision, recall, and accuracy metrics from controlled ground truth.

## PII Types Covered

The tool detects and redacts all PII categories required by the assignment:

- Full names
- Email addresses
- Phone numbers
- Company names
- Physical or mailing addresses
- Social Security Numbers
- Credit card numbers
- Dates of birth
- IP addresses

## How It Works

The redaction engine works directly on DOCX OOXML rather than plain text export. This allows it to preserve the original Word document structure while replacing text inside Word XML parts.

Detection uses a hybrid rule-based approach:

- Regular expressions for structured PII such as emails, SSNs, phone numbers, and IP addresses.
- Luhn validation for credit card candidates to reduce false positives.
- Contextual DOB detection, so ordinary business dates in the prospectus are not treated as birth dates.
- Conservative heuristics for names, company names, and addresses.
- A consistency pass that reapplies known replacements to repeated values across the document.

The project intentionally avoids large NER model downloads so it remains easy to run and deploy on free cloud tiers. The tradeoff is that rare names or unusual addresses may require adding a dictionary entry or another detector rule.

## Project Structure

```text
pii_redaction/
  detectors.py          PII detection rules and overlap resolution
  replacements.py       Deterministic fake value generation
  docx_processor.py     DOCX OOXML scanning and replacement pipeline
  evaluation.py         Metric and report generation helpers
  gold_fixture.py       Controlled labeled fixture for true metrics

app.py                  Web upload/download app
redact_pii.py           CLI entry point
scripts/run_evaluation_fixture.py
tests/test_redaction.py
render.yaml             Render free-tier deployment config
Procfile                Railway/Procfile-compatible start command
EVALUATION.md           Evaluation strategy and current metrics
outputs/                Final generated artifacts
```

## Run Locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the CLI on a DOCX file:

```bash
python redact_pii.py "Red Herring Prospectus.docx" --output outputs/red_herring_prospectus_redacted.docx
```

The command generates:

- Redacted DOCX
- JSON run audit
- Markdown evaluation report
- DOCX evaluation report

## Web App

Start the upload/download interface:

```bash
python app.py
```

Open `http://localhost:8000`, upload a `.docx`, and download:

- The redacted DOCX
- The evaluation report DOCX
- The JSON run audit

## Evaluation

The evaluation is split into two clearly labeled parts:

1. **Controlled gold fixture:** known PII labels and known non-PII negatives. This is the only source used for true precision, recall, and accuracy.
2. **Prospectus audit:** replacement counts, residual detected-original checks, and repeated-value consistency checks for the supplied Red Herring Prospectus.

Current controlled-fixture metrics:

| Metric | Value |
| --- | ---: |
| True positives | 22 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 100.00% |
| Recall | 100.00% |
| Accuracy | 100.00% |

These values apply only to the controlled fixture and are not claimed as real-world benchmark accuracy.

Current prospectus audit:

| Audit item | Value |
| --- | ---: |
| Total replacements | 321 |
| XML parts scanned | 150 |
| Paragraphs scanned | 4864 |
| Residual detected originals | 0 |
| Detected-candidate replacement rate | 100.00% |

Prospectus precision, recall, and accuracy are not claimed because the supplied prospectus does not include human-labeled ground truth.

Run the fixture evaluation:

```bash
python scripts/run_evaluation_fixture.py
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Deployment

The app is ready for free-tier deployment on Render.

Current deployment: https://pii-redaction-tool-bomu.onrender.com

Render configuration is included in `render.yaml`:

- Build command: `pip install -r requirements.txt`
- Start command: `python app.py`
- Runtime: Python 3.11

After connecting the GitHub repository to Render, the generated Render URL can be used as the deployed application link.

## Final Artifacts

The repository includes the generated assignment artifacts:

- `outputs/red_herring_prospectus_redacted_submission.docx`
- `outputs/evaluation_report_submission.docx`
- `outputs/evaluation_report_submission.md`

The raw source prospectus and JSON mapping reports are intentionally not published in the repository because they can contain sensitive original values.

## Extending the Tool

To add a new PII type:

1. Add a detector in `pii_redaction/detectors.py`.
2. Add fake replacement generation in `pii_redaction/replacements.py`.
3. Add gold-fixture examples in `pii_redaction/gold_fixture.py`.
4. Add or update tests in `tests/test_redaction.py`.
