"""PII detectors used by the DOCX redaction pipeline.

The project intentionally uses deterministic regex and heuristics instead of a
large NER model so it can run on free deployment tiers without model downloads.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Iterable


@dataclass(frozen=True)
class Entity:
    start: int
    end: int
    entity_type: str
    text: str
    confidence: float
    rule: str


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

IPV6_CANDIDATE_RE = re.compile(
    r"(?<![A-Fa-f0-9:.])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}"
    r"(?![A-Fa-f0-9:])"
)

PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?"
    r"(?:[6-9]\d{4}[\s.-]?\d{5}|\(?[6-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4}|[6-9]\d{9})(?!\w)"
)

CREDIT_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

DATE_VALUE = (
    r"(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
    r"\d{1,2}\s+(?:Jan|January|Feb|February|Mar|March|Apr|April|May|Jun|June|"
    r"Jul|July|Aug|August|Sep|Sept|September|Oct|October|Nov|November|"
    r"Dec|December)\s+\d{2,4}|"
    r"(?:Jan|January|Feb|February|Mar|March|Apr|April|May|Jun|June|Jul|July|"
    r"Aug|August|Sep|Sept|September|Oct|October|Nov|November|Dec|December)"
    r"\s+\d{1,2},?\s+\d{2,4})"
)

DOB_RE = re.compile(
    rf"\b(?:date\s+of\s+birth|birth\s+date|dob|born\s+on)\s*[:\-]?\s*({DATE_VALUE})",
    re.IGNORECASE,
)

ADDRESS_KEYWORD_RE = re.compile(
    r"\b(?:registered office|corporate office|residential address|residence|"
    r"mailing address|address|located at|office at)\b\s*[:\-]?\s*"
    r"([^.;\n\r]{12,180}(?:\d{5,6})?)",
    re.IGNORECASE,
)

STREET_ADDRESS_RE = re.compile(
    r"\b\d{1,5}[A-Za-z]?\s+"
    r"[A-Z][A-Za-z0-9&'(),./\-\s]{2,90}?\s+"
    r"(?:Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|Lane|Ln\.?|Drive|Dr\.?|"
    r"Boulevard|Blvd\.?|Block|Sector|Nagar|Colony|Layout|Phase|Complex|"
    r"Building|Tower|Floor)\b"
    r"(?:[, ]+[A-Z][A-Za-z .-]{2,40}){0,3}"
    r"(?:[, -]+\d{5,6})?",
)

COMPANY_SUFFIX = (
    r"(?:Private\s+Limited|Pvt\.?\s+Ltd\.?|Limited|Ltd\.?|LLP|Inc\.?|LLC|"
    r"Corporation|Corp\.?|Company|Co\.?|Bank|Technologies|Services|Solutions)"
)

COMPANY_RE = re.compile(
    rf"\b[A-Z][A-Za-z0-9&'()/\-]+"
    rf"(?:\s+[A-Z][A-Za-z0-9&'()/\-]+){{0,7}}\s+{COMPANY_SUFFIX}\b"
)

HONORIFIC_NAME_RE = re.compile(
    r"\b(?:Mr|Ms|Mrs|Dr|Prof)\.?\s+"
    r"[A-Z][a-z]{1,}(?:\s+[A-Z][a-z]{1,}){1,3}\b"
)

PERSON_CANDIDATE_RE = re.compile(
    r"\b[A-Z][a-z]{1,}(?:\s+[A-Z][a-z]{1,}){1,3}\b"
)

COMMON_FIRST_NAMES = {
    "Aaditya",
    "Aakash",
    "Aarav",
    "Aarti",
    "Abhay",
    "Abhishek",
    "Aditya",
    "Aishwarya",
    "Ajay",
    "Akash",
    "Akhil",
    "Amit",
    "Ananya",
    "Anil",
    "Anita",
    "Anjali",
    "Ankit",
    "Ankur",
    "Anmol",
    "Anuj",
    "Apoorva",
    "Arjun",
    "Arpita",
    "Ashish",
    "Avinash",
    "Bhavesh",
    "Cherag",
    "Chitra",
    "Deepak",
    "Devansh",
    "Divya",
    "Eric",
    "Gaurav",
    "Harsh",
    "Hitesh",
    "Isha",
    "Karan",
    "Kavita",
    "Kunal",
    "Mahesh",
    "Manish",
    "Meera",
    "Mohit",
    "Neha",
    "Nikhil",
    "Nisha",
    "Pooja",
    "Pragya",
    "Parag",
    "Prakash",
    "Pranav",
    "Pravin",
    "Priya",
    "Pushpa",
    "Rahul",
    "Raj",
    "Rajesh",
    "Rakesh",
    "Rashi",
    "Rohan",
    "Rohit",
    "Sachin",
    "Sakshi",
    "Sanjay",
    "Sarthak",
    "Sharmila",
    "Sheetal",
    "Shreya",
    "Siddharth",
    "Sneha",
    "Suresh",
    "Tushar",
    "Varun",
    "Vikram",
    "Vishal",
}

PERSON_STOPWORDS = {
    "About",
    "Act",
    "Annexure",
    "Application",
    "Board",
    "Business",
    "Capital",
    "Chapter",
    "Company",
    "Corporate",
    "Date",
    "Directors",
    "Draft",
    "Equity",
    "Financial",
    "General",
    "Government",
    "Group",
    "India",
    "Indian",
    "Issue",
    "Limited",
    "Management",
    "Offer",
    "Order",
    "Private",
    "Prospectus",
    "Red",
    "Registered",
    "Registrar",
    "Report",
    "Reserve",
    "Risk",
    "Schedule",
    "Section",
    "Securities",
    "Share",
    "Table",
    "Ticket",
}

ORG_OR_ADDRESS_WORDS = {
    "Bank",
    "Board",
    "Branch",
    "Building",
    "Capital",
    "Company",
    "Complex",
    "Corporation",
    "Floor",
    "Fund",
    "Group",
    "House",
    "India",
    "Limited",
    "LLP",
    "Ltd",
    "Nagar",
    "Office",
    "Private",
    "Road",
    "SEBI",
    "Services",
    "Solutions",
    "Street",
    "Tower",
    "Website",
}

GENERIC_COMPANY_PREFIXES = {
    "And",
    "Formerly",
    "Our",
    "Private",
    "Public",
    "Stock",
    "The",
    "This",
}

GENERIC_COMPANY_VALUES = {
    "Our Company",
    "This Company",
    "The Company",
    "Private Limited",
    "Public Limited",
}


def detect_entities(text: str) -> list[Entity]:
    """Return non-overlapping PII entities found in one paragraph of text."""

    candidates: list[Entity] = []
    candidates.extend(_regex_entities(text, EMAIL_RE, "email", 0.99, "email_regex"))
    candidates.extend(_regex_entities(text, SSN_RE, "ssn", 0.99, "ssn_regex"))
    candidates.extend(_regex_entities(text, IPV4_RE, "ip_address", 0.98, "ipv4_regex"))
    candidates.extend(_ipv6_entities(text))
    candidates.extend(_phone_entities(text))
    candidates.extend(_credit_card_entities(text))
    candidates.extend(_dob_entities(text))
    candidates.extend(_address_entities(text))
    candidates.extend(_company_entities(text))
    candidates.extend(_name_entities(text))
    return resolve_overlaps(candidates)


def resolve_overlaps(candidates: Iterable[Entity]) -> list[Entity]:
    priority = {
        "email": 100,
        "credit_card": 95,
        "ssn": 95,
        "ip_address": 90,
        "phone": 85,
        "dob": 80,
        "address": 75,
        "company": 70,
        "person": 60,
    }
    ordered = sorted(
        candidates,
        key=lambda e: (e.start, -(e.end - e.start), -priority.get(e.entity_type, 0)),
    )
    accepted: list[Entity] = []
    occupied: list[range] = []
    for entity in ordered:
        span = range(entity.start, entity.end)
        if any(_ranges_overlap(span, used) for used in occupied):
            continue
        accepted.append(entity)
        occupied.append(span)
    return sorted(accepted, key=lambda e: e.start)


def _regex_entities(
    text: str, pattern: re.Pattern[str], entity_type: str, confidence: float, rule: str
) -> list[Entity]:
    return [
        Entity(m.start(), m.end(), entity_type, m.group(0), confidence, rule)
        for m in pattern.finditer(text)
        if m.group(0).strip()
    ]


def _phone_entities(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for match in PHONE_RE.finditer(text):
        value = match.group(0).strip()
        digits = re.sub(r"\D", "", value)
        if len(digits) < 10 or len(digits) > 13:
            continue
        local_digits = digits[-10:]
        if not local_digits.startswith(("6", "7", "8", "9")):
            continue
        if len(set(local_digits)) <= 2:
            continue
        entities.append(Entity(match.start(), match.end(), "phone", value, 0.92, "phone_regex"))
    return entities


def _ipv6_entities(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for match in IPV6_CANDIDATE_RE.finditer(text):
        value = match.group(0)
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        if parsed.version == 6:
            entities.append(
                Entity(match.start(), match.end(), "ip_address", value, 0.94, "ipv6_regex")
            )
    return entities


def _credit_card_entities(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for match in CREDIT_CARD_CANDIDATE_RE.finditer(text):
        value = match.group(0).strip()
        digits = re.sub(r"\D", "", value)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if _luhn_valid(digits):
            entities.append(
                Entity(match.start(), match.end(), "credit_card", value, 0.97, "luhn_card")
            )
    return entities


def _dob_entities(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for match in DOB_RE.finditer(text):
        value = match.group(1).strip()
        start = match.start(1)
        entities.append(Entity(start, start + len(value), "dob", value, 0.9, "dob_context"))
    return entities


def _address_entities(text: str) -> list[Entity]:
    entities = [
        entity
        for entity in _street_address_entities(text)
        if _looks_like_address(entity.text)
    ]
    for match in ADDRESS_KEYWORD_RE.finditer(text):
        value = match.group(1).strip(" ,")
        if len(value) < 12:
            continue
        if not _looks_like_address(value):
            continue
        if len(value.split()) > 28:
            value = " ".join(value.split()[:28])
        start = match.start(1)
        entities.append(Entity(start, start + len(value), "address", value, 0.78, "address_context"))
    return entities


def _street_address_entities(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for match in STREET_ADDRESS_RE.finditer(text):
        start = match.start()
        end = _extend_street_address_end(text, start, match.end())
        value = text[start:end].strip(" ,")
        if not value:
            continue
        entities.append(
            Entity(start, start + len(value), "address", value, 0.84, "street_address")
        )
    return entities


def _extend_street_address_end(text: str, start: int, initial_end: int) -> int:
    max_end = min(len(text), start + 180)
    sentence_end = max_end
    for delimiter in ".;\n\r":
        index = text.find(delimiter, initial_end)
        if index != -1:
            sentence_end = min(sentence_end, index)

    candidate = text[start:sentence_end].strip(" ,")
    has_postal_code = bool(re.search(r"\b\d{5,6}\b", candidate))
    if candidate.count(",") >= 2 and has_postal_code and _looks_like_address(candidate):
        return start + len(candidate)
    return initial_end


def _company_entities(text: str) -> list[Entity]:
    entities: list[Entity] = []
    for match in COMPANY_RE.finditer(text):
        value = match.group(0).strip()
        start = match.start()
        prefix_match = re.match(r"^(?:Formerly|formerly)\s+", value)
        if prefix_match:
            start += prefix_match.end()
            value = value[prefix_match.end() :].strip()
        normalized = " ".join(value.split())
        words = normalized.split()
        if len(words) < 2:
            continue
        if normalized in GENERIC_COMPANY_VALUES:
            continue
        if words[0].rstrip(".,") in GENERIC_COMPANY_PREFIXES:
            continue
        if normalized.endswith(" Company") and text[match.end() : match.end() + 20].lower().startswith(" secretary"):
            continue
        if normalized.count("Private Limited") > 1 or normalized.count("Limited") > 2:
            continue
        entities.append(
            Entity(start, start + len(value), "company", value, 0.9, "company_suffix")
        )
    return entities


def _name_entities(text: str) -> list[Entity]:
    entities = _regex_entities(text, HONORIFIC_NAME_RE, "person", 0.91, "honorific_name")
    for match in PERSON_CANDIDATE_RE.finditer(text):
        value = match.group(0)
        words = value.split()
        if len(words) < 2 or len(words) > 4:
            continue
        if words[0] not in COMMON_FIRST_NAMES:
            continue
        if any(word.rstrip(".") in ORG_OR_ADDRESS_WORDS for word in words):
            continue
        if words[0] in PERSON_STOPWORDS or words[-1] in PERSON_STOPWORDS:
            continue
        entities.append(Entity(match.start(), match.end(), "person", value, 0.82, "first_name_list"))
    return entities


def _luhn_valid(digits: str) -> bool:
    checksum = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _looks_like_address(value: str) -> bool:
    lowered = value.lower()
    reject_phrases = {
        "address the rise",
        "amount equivalent",
        "bid amount",
        "cap price",
        "floor price",
        "history and certain",
        "per annum",
        "same state",
        "working days",
    }
    if any(phrase in lowered for phrase in reject_phrases):
        return False
    address_words = {
        "apartment",
        "avenue",
        "block",
        "building",
        "colony",
        "complex",
        "floor",
        "lane",
        "nagar",
        "park",
        "phase",
        "road",
        "sector",
        "street",
        "tower",
    }
    location_words = {
        "ahmednagar",
        "bengaluru",
        "cantonment",
        "delhi",
        "india",
        "maharashtra",
        "mumbai",
        "pune",
        "springfield",
    }
    has_postal_code = bool(re.search(r"\b\d{3}\s?\d{3}\b|\b\d{5}(?:-\d{4})?\b", value))
    has_street_number = bool(re.search(r"\b\d{1,5}[A-Za-z]?\s+[A-Z]", value))
    has_address_word = any(
        re.search(rf"\b{re.escape(word)}\b", lowered)
        for word in address_words
    )
    has_location = any(word in lowered for word in location_words)
    has_commas = value.count(",") >= 2
    return (
        has_postal_code and (has_address_word or has_location or has_commas)
        or has_street_number and has_address_word
        or has_address_word and has_location and value.count(",") >= 1
    )


def _ranges_overlap(first: range, second: range) -> bool:
    return first.start < second.stop and second.start < first.stop
