"""
services/wazuh_compat.py
Known Wazuh Manager parser quirks that are NOT standard-XML violations
and therefore can't be caught by parsing with lxml — only by actually
comparing against real, empirically-confirmed failures.

Wazuh's rule/decoder file upload endpoint (PUT /rules/files/{filename})
does not use a strict, spec-compliant XML parser under the hood for its
own validation; it appears to use (or share failure paths with) its
custom OS_XML reader, which has known gaps standard XML libraries don't.
A file can be 100% well-formed XML (verified with lxml) and still be
rejected with a generic, unhelpful "XML syntax error" (API error code
1113) because of a construct OS_XML itself can't handle.

This module is a running list of such confirmed-bad constructs, checked
locally BEFORE upload so the person gets an immediate, specific warning
naming the offending rule instead of Wazuh's opaque error after a wasted
round-trip. It is deliberately conservative — only patterns that have
actually been observed to break a real push are listed. It is NOT a
general "is this good XML" validator (see xml_parser.py / lxml for
that); it's a build-up of tribal knowledge about this ONE API's quirks.
"""

from __future__ import annotations

import re

# Each entry: (compiled regex over the RAW (already-unescaped) text a
# rule stores for a given field, human-readable reason, confirmed-by note).
#
# NOTE: these patterns are checked against the *decoded* string (i.e.
# what's stored in MongoDB, e.g. doc['regex']) — not the escaped XML
# text — since that's the same representation both save-time (builder.py)
# and push-time (wazuh_api.py) already have on hand.
_KNOWN_BAD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r'\(\?>|\(\?&gt;'),
        'Mengandung PCRE2 atomic group "(?>...)" — dikonfirmasi menyebabkan '
        'Wazuh Manager menolak file dengan "XML syntax error" (kode 1113) '
        'walau isinya valid sebagai XML standar.',
    ),
]

# Which rule document fields can contain a PCRE2/regex-like pattern and
# are therefore worth scanning.
_SCANNABLE_FIELDS = ('regex', 'match', 'prematch')


def scan_rule_doc(doc: dict) -> list[str]:
    """
    Check one rule document's regex-bearing fields against known-bad
    Wazuh-parser-breaking constructs. Returns a list of human-readable
    warning strings (empty if nothing suspicious found). Also checks
    each entry in `fields` and `urls` (which carry their own `value`).
    """
    warnings: list[str] = []

    def _check(value: str, where: str):
        if not value:
            return
        for pattern, reason in _KNOWN_BAD_PATTERNS:
            if pattern.search(value):
                warnings.append(f'{where}: {reason}')

    for field_name in _SCANNABLE_FIELDS:
        _check(doc.get(field_name) or '', f'field <{field_name}>')

    for f in doc.get('fields') or []:
        _check(f.get('value') or '', f'field name="{f.get("name")}"')

    for u in doc.get('urls') or []:
        _check(u.get('value') or '', 'url')

    return warnings


def scan_rule_docs(docs: list[dict]) -> dict[int, list[str]]:
    """Scan multiple rule documents; returns {rule_id: [warnings]} for
    only the ones that have at least one warning."""
    out: dict[int, list[str]] = {}
    for doc in docs:
        warnings = scan_rule_doc(doc)
        if warnings:
            rule_id = doc.get('rule_id')
            if isinstance(rule_id, int):
                out[rule_id] = warnings
    return out