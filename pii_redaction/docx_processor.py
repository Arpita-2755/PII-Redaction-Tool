"""DOCX processing that replaces PII while preserving Word structure."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

from lxml import etree

from .detectors import Entity, detect_entities
from .replacements import ReplacementFactory


WORD_XML_PART_RE = re.compile(
    r"^word/(document|header\d+|footer\d+|footnotes|endnotes|comments)\.xml$"
)

WORD_NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"


def redact_docx(
    input_path: str | Path,
    output_path: str | Path,
    report_json_path: str | Path | None = None,
) -> dict:
    """Redact PII in a DOCX and write a redacted copy.

    Returns a run report containing counts, examples, and a replacement mapping.
    """

    input_path = Path(input_path)
    output_path = Path(output_path)
    factory = ReplacementFactory()
    all_entities: list[dict] = []
    counts: Counter[str] = Counter()
    paragraphs_scanned = 0
    xml_parts_scanned = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_docx = Path(tmp) / f"first_pass_{output_path.name}"
        second_pass_docx = Path(tmp) / f"second_pass_{output_path.name}"
        with zipfile.ZipFile(input_path, "r") as zin, zipfile.ZipFile(
            tmp_docx, "w", zipfile.ZIP_DEFLATED
        ) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if WORD_XML_PART_RE.match(item.filename):
                    xml_parts_scanned += 1
                    redacted_xml, part_entities, part_paragraphs = _redact_xml_part(
                        data, item.filename, factory
                    )
                    data = redacted_xml
                    paragraphs_scanned += part_paragraphs
                    for entity in part_entities:
                        counts[entity["type"]] += 1
                        all_entities.append(entity)
                zout.writestr(item, data)

        repeat_entities = _replace_known_values_docx(tmp_docx, second_pass_docx, all_entities)
        if repeat_entities:
            for entity in repeat_entities:
                counts[entity["type"]] += 1
                all_entities.append(entity)
            shutil.copyfile(second_pass_docx, output_path)
        else:
            shutil.copyfile(tmp_docx, output_path)

    residuals = _find_residual_originals(output_path, all_entities)
    total = sum(counts.values())
    replacement_rate = (total - len(residuals)) / total if total else 1.0
    report = {
        "input": str(input_path),
        "output": str(output_path),
        "paragraphs_scanned": paragraphs_scanned,
        "xml_parts_scanned": xml_parts_scanned,
        "total_replacements": total,
        "counts_by_type": dict(sorted(counts.items())),
        "residual_original_values": residuals,
        "detected_candidate_replacement_rate": replacement_rate,
        "entities": all_entities,
        "mapping": factory.export_mapping(),
    }

    if report_json_path:
        report_json_path = Path(report_json_path)
        report_json_path.parent.mkdir(parents=True, exist_ok=True)
        report_json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report


def extract_docx_text(input_path: str | Path) -> str:
    """Extract visible text from DOCX Word XML parts."""

    chunks: list[str] = []
    with zipfile.ZipFile(input_path, "r") as zin:
        for item in zin.infolist():
            if not WORD_XML_PART_RE.match(item.filename):
                continue
            root = etree.fromstring(zin.read(item.filename))
            for paragraph in root.xpath(".//w:p", namespaces=WORD_NS):
                text = "".join(node.text or "" for node in paragraph.xpath(".//w:t", namespaces=WORD_NS))
                if text:
                    chunks.append(text)
    return "\n".join(chunks)


def _redact_xml_part(
    data: bytes, part_name: str, factory: ReplacementFactory
) -> tuple[bytes, list[dict], int]:
    parser = etree.XMLParser(resolve_entities=False, recover=True)
    root = etree.fromstring(data, parser=parser)
    part_entities: list[dict] = []
    paragraphs = root.xpath(".//w:p", namespaces=WORD_NS)

    for paragraph_index, paragraph in enumerate(paragraphs, start=1):
        text_nodes = paragraph.xpath(".//w:t", namespaces=WORD_NS)
        if not text_nodes:
            continue
        paragraph_text, spans = _join_text_nodes(text_nodes)
        entities = detect_entities(paragraph_text)
        if not entities:
            continue
        _apply_replacements(text_nodes, spans, entities, factory)
        for entity in entities:
            replacement = factory.replacement_for(entity.entity_type, entity.text)
            part_entities.append(
                {
                    "part": part_name,
                    "paragraph": paragraph_index,
                    "type": entity.entity_type,
                    "original": entity.text,
                    "replacement": replacement,
                    "confidence": entity.confidence,
                    "rule": entity.rule,
                }
            )

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True), part_entities, len(paragraphs)


def _replace_known_values_docx(
    input_path: Path, output_path: Path, detected_entities: list[dict]
) -> list[dict]:
    replacements: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entity in detected_entities:
        original = entity["original"]
        replacement = entity["replacement"]
        key = (entity["type"], original)
        if not original or original == replacement or key in seen:
            continue
        seen.add(key)
        replacements.append((entity["type"], original, replacement))

    replacements.sort(key=lambda item: len(item[1]), reverse=True)
    repeat_entities: list[dict] = []

    with zipfile.ZipFile(input_path, "r") as zin, zipfile.ZipFile(
        output_path, "w", zipfile.ZIP_DEFLATED
    ) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if WORD_XML_PART_RE.match(item.filename):
                data, part_entities = _replace_known_values_xml_part(
                    data, item.filename, replacements
                )
                repeat_entities.extend(part_entities)
            zout.writestr(item, data)
    return repeat_entities


def _replace_known_values_xml_part(
    data: bytes, part_name: str, replacements: list[tuple[str, str, str]]
) -> tuple[bytes, list[dict]]:
    parser = etree.XMLParser(resolve_entities=False, recover=True)
    root = etree.fromstring(data, parser=parser)
    repeat_entities: list[dict] = []

    for paragraph_index, paragraph in enumerate(root.xpath(".//w:p", namespaces=WORD_NS), start=1):
        text_nodes = paragraph.xpath(".//w:t", namespaces=WORD_NS)
        if not text_nodes:
            continue
        paragraph_text = "".join(node.text or "" for node in text_nodes)
        redacted_text = paragraph_text
        paragraph_entities: list[dict] = []
        for entity_type, original, replacement in replacements:
            occurrences = redacted_text.count(original)
            if not occurrences:
                continue
            redacted_text = redacted_text.replace(original, replacement)
            for _ in range(occurrences):
                paragraph_entities.append(
                    {
                        "part": part_name,
                        "paragraph": paragraph_index,
                        "type": entity_type,
                        "original": original,
                        "replacement": replacement,
                        "confidence": 0.72,
                        "rule": "global_consistency_pass",
                    }
                )
        if paragraph_entities:
            text_nodes[0].text = redacted_text
            _preserve_space(text_nodes[0])
            for node in text_nodes[1:]:
                node.text = ""
            repeat_entities.extend(paragraph_entities)

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True), repeat_entities


def _join_text_nodes(text_nodes: list[etree._Element]) -> tuple[str, list[tuple[int, int]]]:
    text_parts: list[str] = []
    spans: list[tuple[int, int]] = []
    position = 0
    for node in text_nodes:
        value = node.text or ""
        text_parts.append(value)
        spans.append((position, position + len(value)))
        position += len(value)
    return "".join(text_parts), spans


def _apply_replacements(
    text_nodes: list[etree._Element],
    spans: list[tuple[int, int]],
    entities: list[Entity],
    factory: ReplacementFactory,
) -> None:
    paragraph_text = "".join(node.text or "" for node in text_nodes)
    redacted_text = paragraph_text
    for entity in sorted(entities, key=lambda item: item.start, reverse=True):
        replacement = factory.replacement_for(entity.entity_type, entity.text)
        redacted_text = redacted_text[: entity.start] + replacement + redacted_text[entity.end :]

    # Word often splits a single visual sentence across many runs. Rebuilding the
    # paragraph text in the first run avoids offset drift when several entities
    # are replaced inside the same paragraph.
    text_nodes[0].text = redacted_text
    _preserve_space(text_nodes[0])
    for node in text_nodes[1:]:
        node.text = ""


def _preserve_space(node: etree._Element) -> None:
    value = node.text or ""
    if value[:1].isspace() or value[-1:].isspace():
        node.set(XML_SPACE, "preserve")


def _find_residual_originals(output_path: Path, entities: list[dict]) -> list[dict[str, str]]:
    output_text = extract_docx_text(output_path)
    residuals = []
    seen: set[tuple[str, str]] = set()
    for entity in entities:
        key = (entity["type"], entity["original"])
        if key in seen:
            continue
        seen.add(key)
        if entity["original"] and entity["original"] in output_text:
            residuals.append({"type": entity["type"], "value": entity["original"]})
    return residuals
