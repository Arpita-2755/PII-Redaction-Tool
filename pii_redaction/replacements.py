"""Deterministic fake value generation for PII replacements."""

from __future__ import annotations

import hashlib
import re


FIRST_NAMES = [
    "Aarav",
    "Ananya",
    "Ishaan",
    "Meera",
    "Kabir",
    "Nisha",
    "Riya",
    "Vihaan",
    "Zoya",
    "Neil",
]

LAST_NAMES = [
    "Sharma",
    "Kapoor",
    "Mehta",
    "Rao",
    "Iyer",
    "Khanna",
    "Menon",
    "Nair",
    "Sethi",
    "Verma",
]

COMPANIES = [
    "Northstar Data Labs Pvt Ltd",
    "Bluepeak Analytics Limited",
    "Cedar Finserv LLP",
    "Riverbend Technologies Inc",
    "Summit Retail Solutions",
    "Maple Grove Services Limited",
    "Aurora Capital Advisors LLP",
    "Silverline Systems Pvt Ltd",
]

ADDRESSES = [
    "42 Maple Street, Springfield, IL 62704",
    "18 MG Road, Bengaluru, Karnataka 560001",
    "7 Park Avenue, Mumbai, Maharashtra 400001",
    "221 Lake View Road, Pune, Maharashtra 411001",
    "55 Cedar Lane, Austin, TX 78701",
    "12 Green Park, New Delhi, Delhi 110016",
]

CARD_NUMBERS = [
    "4111 1111 1111 1111",
    "5555 5555 5555 4444",
    "4012 8888 8888 1881",
    "3782 822463 10005",
]


class ReplacementFactory:
    """Create stable fake replacements for each original value."""

    def __init__(self) -> None:
        self.mapping: dict[tuple[str, str], str] = {}

    def replacement_for(self, entity_type: str, value: str) -> str:
        key = (entity_type, _normalize(value))
        if key not in self.mapping:
            replacement = self._generate(entity_type, value)
            if _normalize(replacement).lower() == _normalize(value).lower():
                replacement = self._generate(entity_type, f"{value}:alternate")
            self.mapping[key] = replacement
        return self.mapping[key]

    def export_mapping(self) -> list[dict[str, str]]:
        return [
            {"type": entity_type, "original": original, "replacement": replacement}
            for (entity_type, original), replacement in sorted(self.mapping.items())
        ]

    def _generate(self, entity_type: str, value: str) -> str:
        index = _stable_index(f"{entity_type}:{value}", 10_000)
        if entity_type == "person":
            return _fake_name(value, index)
        if entity_type == "email":
            first = FIRST_NAMES[index % len(FIRST_NAMES)].lower()
            last = LAST_NAMES[(index // 7) % len(LAST_NAMES)].lower()
            return f"{first}.{last}{index % 97}@example.com"
        if entity_type == "phone":
            return _fake_phone(value, index)
        if entity_type == "company":
            return COMPANIES[index % len(COMPANIES)]
        if entity_type == "address":
            return ADDRESSES[index % len(ADDRESSES)]
        if entity_type == "ssn":
            return f"900-{10 + index % 80:02d}-{1000 + index % 9000:04d}"
        if entity_type == "credit_card":
            return CARD_NUMBERS[index % len(CARD_NUMBERS)]
        if entity_type == "dob":
            return _fake_date(value, index)
        if entity_type == "ip_address":
            if ":" in value:
                return _fake_ipv6(index)
            return f"203.0.113.{1 + index % 254}"
        return "[REDACTED]"


def _fake_name(value: str, index: int) -> str:
    honorific_match = re.match(r"^(Mr|Ms|Mrs|Dr|Prof)\.?\s+", value)
    honorific = ""
    if honorific_match:
        honorific = honorific_match.group(0)
    first = FIRST_NAMES[index % len(FIRST_NAMES)]
    last = LAST_NAMES[(index // 5) % len(LAST_NAMES)]
    return f"{honorific}{first} {last}"


def _fake_phone(value: str, index: int) -> str:
    local = f"9{(10_000_0000 + index * 7919) % 1_000_000_000:09d}"
    if "+91" in value or value.strip().startswith("91"):
        return f"+91 {local[:5]} {local[5:]}"
    if re.search(r"\d{3}[-.]\d{3}[-.]\d{4}", value):
        return f"{local[:3]}-{local[3:6]}-{local[6:]}"
    return local


def _fake_date(value: str, index: int) -> str:
    day = 1 + index % 28
    month = 1 + (index // 17) % 12
    year = 1975 + index % 25
    if "/" in value:
        return f"{day:02d}/{month:02d}/{year}"
    if "-" in value and re.search(r"\d{1,2}-\d{1,2}-\d{2,4}", value):
        return f"{day:02d}-{month:02d}-{year}"
    month_names = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ]
    return f"{day} {month_names[month - 1]} {year}"


def _fake_ipv6(index: int) -> str:
    block_one = index % 0x10000
    block_two = (index // 11) % 0x10000
    host = 1 + index % 0xFFFE
    return f"2001:db8:{block_one:x}:{block_two:x}::{host:x}"


def _stable_index(value: str, modulo: int) -> int:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return int(digest[:12], 16) % modulo


def _normalize(value: str) -> str:
    return " ".join(value.strip().split())
