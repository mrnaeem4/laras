"""
services/wazuh_contract.py
Authoritative Wazuh rule XML contract, shared by three consumers:

  1. the LLM prompt (services/ai_utils.py)        -- prevention
  2. the AI draft normalizer (services/ai_utils.py) -- guarantee
  3. the XML generator (services/xml_generator.py)  -- last-resort safety

Source: Wazuh documentation "Rules Syntax"
  https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
extracted 30 September 2026 (Wazuh 4.x).

Why this module exists
----------------------
The AI kept producing syntactically wrong rules, e.g. turning a field-scoped
match into `<field name="url">` when `url` is a STATIC field that has its own
dedicated `<url>` element. Patching each mistake reactively is whack-a-mole.
Instead LARAS owns the schema: one contract, taught to the model (prompt) AND
enforced server-side (normalizer + generator).

Static vs dynamic fields
------------------------
- STATIC fields are decoded by Wazuh itself and have a dedicated element
  (`<url>`, `<srcip>`, `<status>`, ...). Use the element, not `<field name>`.
- DYNAMIC fields are names produced by a decoder's `<order>` and are matched
  with `<field name="X">`.
"""

from __future__ import annotations

# name -> (element_name, supports_type_attribute, supports_negate_attribute)
#
# Notes from the documentation (kept here so nobody has to re-read the page):
#   - `<srcip>` / `<dstip>` are the ONLY static elements with `negate` but NO
#     `type` attribute.
#   - The element is `<protocol>`, NOT `<proto>`.
#   - There is NO `<srcuser>`/`<dstuser>` element; the user element is `<user>`.
#   - `<action>`'s `type` attribute must be OMITTED for a literal string match.
STATIC_FIELDS: dict[str, tuple[str, bool, bool]] = {
    'url':         ('url',         True,  True),
    'id':          ('id',          True,  True),
    'status':      ('status',      True,  True),
    'srcip':       ('srcip',       False, True),
    'dstip':       ('dstip',       False, True),
    'srcport':     ('srcport',     True,  True),
    'dstport':     ('dstport',     True,  True),
    'data':        ('data',        True,  True),
    'extra_data':  ('extra_data',  True,  True),
    'user':        ('user',        True,  True),
    'system_name': ('system_name', True,  True),
    'program_name': ('program_name', True, True),
    'protocol':    ('protocol',    True,  True),
    'hostname':    ('hostname',    True,  True),
    'location':    ('location',    True,  True),
    'action':      ('action',      True,  True),
    'srcgeoip':    ('srcgeoip',    True,  True),
    'dstgeoip':    ('dstgeoip',    True,  True),
}

STATIC_FIELD_NAMES = frozenset(STATIC_FIELDS)

# The URL element is exposed in the Rule Builder UI as its own list, so the
# normalizer routes `url` there rather than into the generic static_fields map.
UI_URL_FIELD = 'url'


def is_static_field(name: str) -> bool:
    return (name or '').strip().lower() in STATIC_FIELD_NAMES


def element_for(name: str):
    """Return (element_name, supports_type, supports_negate) or None."""
    return STATIC_FIELDS.get((name or '').strip().lower())


# ── Prompt cheat-sheet ─────────────────────────────────────────────────
# Injected into the LLM system prompt. Kept deliberately compact: this is
# the finite, stable part of the Wazuh rule syntax that a detector author
# must get right. It is NOT a replacement for the full documentation.
PROMPT_CONTRACT = """\
WAZUH RULE XML CONTRACT (follow exactly):

Element structure:
  <rule id="100000-999999" level="0-16">
    <description>...</description>
    <if_sid>...</if_sid> | <if_group>...</if_group> | <decoded_as>...</decoded_as>
    <match>...</match> | <regex type="pcre2">...</regex>
    <url>...</url> | <status>...</status> | <id>...</id> | <srcip>...</srcip> ...
    <field name="dynamic_field">...</field>
    <group>tag1,tag2,</group>
    <mitre><id>T1190</id></mitre>
  </rule>

STATIC FIELDS have their own element - NEVER write <field name="url"> etc.
Use the dedicated element: <url>, <id>, <status>, <srcip>, <dstip>, <srcport>,
<dstport>, <data>, <extra_data>, <user>, <system_name>, <program_name>,
<protocol>, <hostname>, <location>, <action>, <srcgeoip>, <dstgeoip>.
  - <srcip>/<dstip> take negate="yes" but NO type attribute.
  - <action> must OMIT type for a literal string match.

DYNAMIC FIELDS (names produced by a decoder's <order>, e.g. sysmon.image)
use <field name="X">...</field>. Do not invent decoder field names.

<match> / <regex> match the RAW LOG EVENT and MUST be plain strings:
  - match  default type osmatch
  - regex  default type osregex
  - valid type values: osmatch | osregex | pcre2
  - negate="yes" allowed
NEVER put an object inside match/regex. To match a specific field, use the
static element (for static fields) or <field name> (for dynamic fields).

Correlation (must be used together):
  <if_matched_sid> or <if_matched_group> + frequency + timeframe
  same_srcip / different_srcip / same_url / same_field require frequency+timeframe.
  same_field only works with DYNAMIC fields, not static ones.

Rules:
  - Every rule MUST have a <group> (comma-terminated, e.g. "attack,sql_injection,").
  - Rule id for custom rules: 100000-999999.
  - Use <field name="X" type="pcre2"> for regex on dynamic fields.
"""


def condition_bucket(name: str) -> str:
    """Where a field-scoped condition belongs: 'url' | 'static' | 'dynamic'."""
    key = (name or '').strip().lower()
    if key == UI_URL_FIELD:
        return 'url'
    if key in STATIC_FIELD_NAMES:
        return 'static'
    return 'dynamic'
