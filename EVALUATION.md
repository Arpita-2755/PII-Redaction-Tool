# Evaluation Strategy and Metrics

## Strategy

The supplied Red Herring Prospectus does not include a human-annotated ground-truth label file, so I used a two-part evaluation:

1. A controlled gold fixture with known PII labels and known non-PII negatives. This is the only source used for true precision, recall, and accuracy.
2. A prospectus run audit that records every detected candidate, verifies that detected originals no longer remain in the output, checks repeated-value consistency, and reports per-type replacement counts.

Structured PII is detected with strict regular expressions and validators. Credit cards must pass Luhn validation. Dates of birth are redacted only near DOB context words to avoid treating normal prospectus dates as birth dates. Names, companies, and addresses use conservative heuristics, so the main tradeoff is better precision with some possible missed uncommon names.

## Gold Fixture Metrics

These are entity-level set metrics measured against the controlled fixture ground truth.

- True positives: 19
- False positives: 0
- False negatives: 0
- Precision: 100.00%
- Recall: 100.00%
- Accuracy: 100.00%

| PII Type | TP | FP | FN | Precision | Recall | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| address | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| company | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| credit_card | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| dob | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| email | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| ip_address | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| person | 3 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| phone | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| ssn | 2 | 0 | 0 | 100.00% | 100.00% | 100.00% |

## Prospectus Audit

- Total replacements: 317
- XML parts scanned: 150
- Paragraphs scanned: 4864
- Residual original PII values found after replacement: 0
- Detected-candidate replacement rate: 100.00%
- Prospectus precision/recall/accuracy: not claimed because no human-labeled prospectus ground truth was provided.

## Counts by PII Type

| PII Type | Replacements |
| --- | ---: |
| address | 13 |
| company | 156 |
| email | 52 |
| person | 95 |
| phone | 1 |

## False Positive / False Negative Notes

- Ticket IDs, order numbers, page numbers, and normal financial figures are not redacted unless they match a protected PII type.
- Company names with clear legal suffixes are redacted; generic product or section names are left intact.
- Dates are treated as DOB only when DOB wording is nearby. This improves precision for a prospectus, which contains many business dates.
- Some rare person names without honorifics or first names outside the built-in list may require adding a custom rule or dictionary.

## Residual Check

No original detected PII values were found in the generated output DOCX.
