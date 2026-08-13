# PII Redaction Tool

A DOCX redaction tool that replaces personally identifiable information with realistic fake alternatives while keeping a consistent original-to-fake mapping across the document.

## What It Redacts

- Full names
- Email addresses
- Phone numbers
- Company names
- Physical or mailing addresses
- Social Security Numbers
- Credit card numbers
- Dates of birth
- IP addresses

## Approach

The redaction engine reads the DOCX as OOXML, scans Word text nodes in document, header, footer, footnote, endnote, and comment parts, then writes a redacted DOCX copy. It uses strict regex detectors for structured PII, Luhn validation for credit cards, contextual rules for DOBs and addresses, and conservative name/company heuristics. Each original value is mapped to a deterministic fake replacement so repeated values stay consistent.

This project intentionally avoids heavy NER model downloads so it can deploy on a free cloud tier. The tradeoff is that rare names or addresses without clear context may need an extra dictionary/rule, but the rules are easier to audit and extend.

## Run Locally

```bash
pip install -r requirements.txt
python redact_pii.py "Red Herring Prospectus.docx" --output outputs/red_herring_prospectus_redacted.docx
```

The command also creates:

- `outputs/redaction_run.json`
- `outputs/evaluation_report.md`
- `outputs/evaluation_report.docx`

## Web App

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:8000`, upload a `.docx`, and download the redacted DOCX plus evaluation report.

## Free Deployment

The repo includes `render.yaml` and `Procfile`.

Render setup:

1. Push this repository to GitHub.
2. Create a new Render Web Service from the repo.
3. Use the included settings:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python app.py`
   - Python version: `3.11.9`
4. After deploy, use the Render URL in the submission form.

Railway can also run it with the same `Procfile`.

## Evaluation

The evaluation uses two checks:

- A controlled gold fixture with known PII labels and known non-PII negatives. This is the only source used for true precision, recall, and accuracy.
- A prospectus run audit that counts every detected candidate and verifies that detected original values do not remain in the redacted output.

Run the fixture:

```bash
python scripts/run_evaluation_fixture.py
```

Current gold fixture metrics: 19 true positives, 0 false positives, 0 false negatives, precision 100.00%, recall 100.00%, accuracy 100.00%.

Current prospectus audit: 317 replacements, zero residual detected originals, detected-candidate replacement rate 100.00%. Prospectus precision/recall/accuracy are not claimed because no human-labeled prospectus ground truth was provided.

Run the prospectus:

```bash
python redact_pii.py "Red Herring Prospectus.docx" --output outputs/red_herring_prospectus_redacted.docx
```

## Extending a PII Type

Add a detector rule in `pii_redaction/detectors.py`, add a fake value generator in `pii_redaction/replacements.py`, then add a fixture example in `tests/test_redaction.py`.

## Submission Files

For the Scaler AI Labs form, submit:

- GitHub repo link
- Free cloud deployment link
- `outputs/red_herring_prospectus_redacted_submission.docx`
- `outputs/evaluation_report_submission.docx`
- Resume file
- Original work declaration checkbox
