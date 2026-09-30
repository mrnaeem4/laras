"""
services/xml_parser.py
Bidirectional converter between Wazuh XML files and MongoDB documents.

  parse_decoder_xml(xml_string)  -> list[dict]   (decoder documents)
  parse_rule_xml(xml_string)     -> list[dict]   (rule documents)
  decoder_doc_to_xml(doc)        -> str           (XML string)
  rule_doc_to_xml(doc)           -> str           (XML string)
  build_rule_file_xml(docs)      -> str           (full file, handles multiple <group> wrappers)
  resolve_wrapper_group_name(docs) -> str         (legacy: single wrapper only, kept for callers
                                                    that know a file has exactly one group)
"""

from __future__ import annotations

import logging
import re
import html
import lxml.etree as etree

from services.wazuh_contract import STATIC_FIELDS

logger = logging.getLogger(__name__)


# ── Robust XML parsing helpers ─────────────────────────────────────────

def _preprocess(xml_string: str) -> str:
    r"""
    Pre-process a Wazuh XML string before parsing:

    1. Remove the XML declaration (``<?xml ...?>``) — it cannot appear
       inside a wrapped fragment.
    2. Escape bare ``&`` characters that are NOT already part of a valid
       XML entity reference (``&amp;``, ``&lt;``, ``&gt;``, ``&quot;``,
       ``&apos;``, ``&#…;``).  Many real Wazuh decoder files use literal
       ``&`` inside regex patterns, e.g. ``ip=(\S+)&server=``.
    """
    # Strip XML declaration
    xml_string = re.sub(r'<\?xml[^?]*\?>', '', xml_string).strip()

    # Escape bare & — replace & NOT followed by a valid entity/char ref
    # Valid references: &amp; &lt; &gt; &quot; &apos; &#digits; &#xhex;
    xml_string = re.sub(r'&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)', '&amp;', xml_string)

    return xml_string


def _parse_robust(xml_string: str, wrapper_tag: str) -> etree._Element:
    """
    Attempt to parse XML with increasing permissiveness:

    1. Strict parse of the raw string (handles well-formed single-root files).
    2. Strict parse after wrapping in ``<wrapper_tag>`` (handles multi-root
       files without a single wrapper element).
    3. Recover-mode parse with wrapping + pre-processing (handles files with
       unescaped ``&`` characters and other minor XML violations).

    Raises ``ValueError`` if all attempts fail.
    """
    preprocessed = _preprocess(xml_string)

    attempts = [
        # (xml_to_try, use_recover_parser)
        (xml_string, False),
        (f'<{wrapper_tag}>{preprocessed}</{wrapper_tag}>', False),
        (f'<{wrapper_tag}>{preprocessed}</{wrapper_tag}>', True),
    ]

    last_error: etree.XMLSyntaxError | None = None
    for xml_attempt, recover in attempts:
        try:
            parser = etree.XMLParser(recover=recover, encoding='utf-8')
            root = etree.fromstring(xml_attempt.encode('utf-8'), parser)
            if root is not None:
                return root
        except etree.XMLSyntaxError as exc:
            last_error = exc

    raise ValueError(f'Invalid XML: {last_error}') from last_error

def _escape_wazuh_regex_content(content: str) -> str:
    """Escape XML entities safely without double-encoding."""
    # html.unescape dipanggil lebih dulu untuk mencegah double-encoding 
    # (berjaga-jaga jika XMLGenerator atau DB sudah menyimpan data '&amp;')
    raw_content = html.unescape(content)
    
    # Replace karakter khusus sesuai standar XML.
    # HANYA &, <, > yang wajib di-escape di dalam text node elemen.
    # " dan ' TIDAK perlu di-escape di text node (hanya wajib di dalam
    # attribute value) — meng-escape-nya di sini menyebabkan &quot; /
    # &apos; muncul secara literal di diff/push meskipun XML aslinya bersih.
    raw_content = raw_content.replace("&", "&amp;")
    raw_content = raw_content.replace("<", "&lt;")
    raw_content = raw_content.replace(">", "&gt;")
    
    return raw_content

def encode_wazuh_xml_fields(xml_string: str) -> str:
    """
    Finds fields prone to unescaped characters (regex, match, urls) 
    and encodes them properly for Wazuh.
    """
    # Daftar tag Wazuh yang sering berisi regex, string mentah, atau simbol
    tags_to_encode = ['regex', 'match', 'pcre2', 'prematch', 'url', 'description', 'info']
    tags_pattern = '|'.join(tags_to_encode)
    
    # Menangkap tag pembuka, isinya, dan tag penutup
    pattern = rf'(<(?:{tags_pattern})[^>]*>)(.*?)(</(?:{tags_pattern})>)'

    def replacer(match_obj):
        open_tag = match_obj.group(1)
        content = match_obj.group(2)
        close_tag = match_obj.group(3)
        
        safe_content = _escape_wazuh_regex_content(content)
        return f"{open_tag}{safe_content}{close_tag}"

    return re.sub(pattern, replacer, xml_string, flags=re.DOTALL)

# ── Public parse functions ─────────────────────────────────────────────

def parse_decoder_xml(xml_string: str) -> list[dict]:
    """
    Parse a Wazuh decoder XML file and return a list of decoder documents
    ready for upsert into the ``decoders`` MongoDB collection.

    Handles all common real-world Wazuh decoder file formats:
      - Single bare ``<decoder name="...">`` element
      - ``<decoder_list>`` wrapper with multiple decoders
      - Multiple bare ``<decoder>`` elements without a root wrapper
      - Files with XML comments between decoder elements
      - Files with unescaped ``&`` characters inside regex patterns

    Wazuh explicitly supports "sibling decoders" — multiple <decoder>
    elements sharing the exact same `name` attribute, used together
    (often with offset="after_regex"/"after_parent") to progressively
    extract more fields from the same log
    (https://documentation.wazuh.com/current/user-manual/ruleset/decoders/sibling-decoders.html).
    Decoders have NO other stable identifier from Wazuh (unlike rules,
    which carry a unique `id`), so each doc is tagged with `_seq` — its
    0-based position among ALL decoders in this file — which callers use
    together with (filename, name) to tell same-named siblings apart
    instead of treating `name` alone as a unique key. This is inherently
    best-effort: if a file is heavily reordered on the Wazuh side between
    pulls, `_seq` can drift and a sibling may be matched against the
    wrong previously-synced document.
    """
    root = _parse_robust(xml_string.strip(), 'decoder_list')

    # Collect all <decoder> elements regardless of wrapper tag
    if root.tag == 'decoder':
        decoder_els = [root]
    else:
        decoder_els = root.findall('.//decoder')

    docs = []
    for seq, el in enumerate(decoder_els):
        doc = _parse_decoder_element(el)
        if doc:
            doc['_seq'] = seq
            docs.append(doc)
    return docs


def _parse_decoder_element(el: etree._Element) -> dict | None:
    name = el.get('name', '').strip()
    if not name:
        return None

    doc: dict = {'name': name}

    def _text(tag: str) -> str:
        child = el.find(tag)
        return child.text.strip() if child is not None and child.text else ''

    def _attr(tag: str, attr: str) -> str:
        child = el.find(tag)
        return child.get(attr, '').strip() if child is not None else ''

    doc['parent'] = _text('parent')
    doc['type'] = _text('type')
    doc['program_name'] = _text('program_name')
    doc['program_name_type'] = _attr('program_name', 'type')

    doc['prematch'] = _text('prematch')
    doc['prematch_type'] = _attr('prematch', 'type')
    doc['prematch_offset'] = _attr('prematch', 'offset')

    doc['regex'] = _text('regex')
    doc['regex_type'] = _attr('regex', 'type')
    doc['regex_offset'] = _attr('regex', 'offset')

    doc['order'] = _text('order')
    doc['fts'] = _text('fts')
    doc['ftscomment'] = _text('ftscomment')
    doc['accumulate'] = el.find('accumulate') is not None
    use_own = el.find('use_own_name')
    doc['use_own_name'] = (
        use_own is not None and (use_own.text or '').strip().lower() == 'true'
    )

    return doc


def parse_rule_xml(xml_string: str) -> list[dict]:
    """
    Parse a Wazuh rule XML file and return a list of rule documents
    ready for upsert into the ``rules`` MongoDB collection.

    Handles all common real-world Wazuh rule file formats:
      - Single bare ``<rule id="...">`` element
      - ``<group name="...">`` wrapper with multiple rules
      - Multiple bare ``<rule>`` or ``<group>`` elements without a root wrapper
      - Files with XML comments between rule elements
      - Files with unescaped ``&`` characters inside regex/match patterns
    """
    root = _parse_robust(xml_string.strip(), 'ruleset')

    if root.tag == 'rule':
        rule_els = [root]
    else:
        rule_els = root.findall('.//rule')

    docs = []
    for el in rule_els:
        doc = _parse_rule_element(el)
        if doc:
            docs.append(doc)
    return docs


def _wrapper_group_name(el: etree._Element) -> str:
    """
    Walk up the ancestor chain to find the nearest enclosing
    ``<group name="...">`` wrapper. Real-world Wazuh rule files very
    commonly define the group once on the wrapper and omit an inner
    <group> on each individual <rule>, e.g.:

        <group name="local,syslog,ssh,">
          <rule id="100001" level="10">
            <description>...</description>
            <!-- no <group> here — it's inherited from the wrapper -->
          </rule>
        </group>

    Without this, every rule parsed from such a file would end up with
    an empty `group` / `groups` field.
    """
    parent = el.getparent()
    while parent is not None:
        if parent.tag == 'group':
            name = parent.get('name', '').strip()
            if name:
                return name
        parent = parent.getparent()
    return ''


def _parse_rule_element(el: etree._Element) -> dict | None:
    rule_id = el.get('id', '').strip()
    if not rule_id:
        return None

    def _text(tag: str) -> str:
        child = el.find(tag)
        return child.text.strip() if child is not None and child.text else ''

    def _attr(tag: str, attr: str) -> str:
        child = el.find(tag)
        return child.get(attr, '').strip() if child is not None else ''

    doc: dict = {
        'rule_id': int(rule_id),
        'level': int(el.get('level', '0') or '0'),
        'frequency': el.get('frequency', '').strip(),
        'timeframe': el.get('timeframe', '').strip(),
        'ignore': el.get('ignore', '').strip(),
        'overwrite': el.get('overwrite', '').strip(),
        'noalert': el.get('noalert', '').strip(),
        'maxsize': el.get('maxsize', '').strip(),
        'description': _text('description'),
        'decoded_as': _text('decoded_as'),
        'if_sid': _text('if_sid'),
        'if_group': _text('if_group'),
        'if_level': _text('if_level'),
        'if_matched_sid': _text('if_matched_sid'),
        'if_matched_group': _text('if_matched_group'),
        'match': _text('match'),
        'match_type': _attr('match', 'type'),
        'match_negate': _attr('match', 'negate') == 'yes',
        'regex': _text('regex'),
        'regex_type': _attr('regex', 'type'),
    }

    # <info> — a rule may have zero, one, or several <info> elements.
    # generate_rule() accepts either a single string (with info_type) or a
    # list of {value, type} dicts, so mirror whichever shape was in the XML
    # instead of always collapsing to the first element (which used to
    # silently drop every <info> after the first).
    info_els = el.findall('info')
    if len(info_els) > 1:
        doc['info'] = [
            {'value': (i.text or '').strip(), 'type': i.get('type', '').strip()}
            for i in info_els if i.text and i.text.strip()
        ]
        doc['info_type'] = ''
    elif len(info_els) == 1 and info_els[0].text and info_els[0].text.strip():
        doc['info'] = info_els[0].text.strip()
        doc['info_type'] = info_els[0].get('type', '').strip()
    else:
        doc['info'] = ''
        doc['info_type'] = ''

    # <field name="..."> conditions
    fields = []
    for f in el.findall('field'):
        fname = f.get('name', '').strip()
        fval = (f.text or '').strip()
        if fname and fval:
            fields.append({
                'name': fname,
                'value': fval,
                'type': f.get('type', '').strip(),
                'negate': f.get('negate', '') == 'yes',
            })
    doc['fields'] = fields

    # <url> conditions — list of dicts
    urls = []
    for u in el.findall('url'):
        uval = (u.text or '').strip()
        if uval:
            urls.append({
                'value': uval,
                'type': u.get('type', '').strip(),
                'negate': u.get('negate', '') == 'yes',
            })
    doc['urls'] = urls

    # Generic STATIC-field elements (<srcip>, <status>, <id>, <data>, ...).
    # These have dedicated elements and were previously DROPPED on pull —
    # which silently lost them on a pull/push round-trip. `url` is excluded
    # because it is already parsed into `urls` above. See
    # services/wazuh_contract.py for the authoritative element list.
    static_fields: dict = {}
    for _name, (_element, _supports_type, _supports_negate) in STATIC_FIELDS.items():
        if _element == 'url':
            continue
        entries = []
        for child in el.findall(_element):
            cval = (child.text or '').strip()
            if not cval:
                continue
            entry = {'value': cval}
            ctype = child.get('type', '').strip()
            if ctype:
                entry['type'] = ctype
            if child.get('negate', '') == 'yes':
                entry['negate'] = True
            entries.append(entry)
        if entries:
            static_fields[_name] = entries
    doc['static_fields'] = static_fields

    # <list field="..." lookup="...">path</list> — threat intel / IP lists
    lists = []
    for lst in el.findall('list'):
        lfield = lst.get('field', '').strip()
        lpath = (lst.text or '').strip()
        if lfield and lpath:
            lists.append({
                'field': lfield,
                'lookup': lst.get('lookup', '').strip(),
                'path': lpath,
            })
    doc['lists'] = lists

    # <time> — time-window matching
    doc['time'] = _text('time')

    # Correlation helpers (self-closing elements)
    doc['same_srcip'] = el.find('same_srcip') is not None
    doc['different_srcip'] = el.find('different_srcip') is not None
    doc['same_url'] = el.find('same_url') is not None
    doc['same_fields'] = [
        sf.text.strip() for sf in el.findall('same_field')
        if sf.text and sf.text.strip()
    ]

    # <group> — split comma-separated into an array; keep original string too.
    # If the rule has no <group> of its own, fall back to the group name
    # inherited from an enclosing <group name="..."> wrapper (see
    # _wrapper_group_name for why this matters).
    group_text = _text('group') or _wrapper_group_name(el)
    doc['group'] = group_text
    doc['groups'] = [g.strip() for g in group_text.split(',') if g.strip()]

    # Separately record the enclosing <group name="..."> wrapper's own
    # name, regardless of whether this rule has its own <group> tag.
    # Real-world Wazuh files very commonly wrap several rules under one
    # broad wrapper name (e.g. "base_rule,") while each individual rule
    # carries a more specific <group> of its own (e.g.
    # "invalid_http_method,"). Rebuilding the file must use THIS field
    # for the wrapper — never a rule's own `group` — or the wrapper name
    # silently drifts to whatever the first rule's own group happens to
    # be on every pull/push round-trip. See build_rule_file_xml().
    doc['_wrapper_group'] = _wrapper_group_name(el)

    # <mitre><id>…</id></mitre>
    mitre_el = el.find('mitre')
    if mitre_el is not None:
        doc['mitre_ids'] = [
            mid.text.strip()
            for mid in mitre_el.findall('id')
            if mid.text and mid.text.strip()
        ]
    else:
        doc['mitre_ids'] = []

    # <options>
    doc['options'] = [
        opt.text.strip()
        for opt in el.findall('options')
        if opt.text and opt.text.strip()
    ]

    return doc


# ── MongoDB document  →  XML ──────────────────────────────────────────

def resolve_wrapper_group_name(docs: list[dict]) -> str:
    """
    LEGACY / single-wrapper only. Determine ONE ``<group name="...">``
    wrapper name for a file, given its rule documents.

    Superseded by `build_rule_file_xml`, which correctly handles files
    containing MULTIPLE distinct wrapper groups by rendering one
    ``<group>`` block per distinct `_wrapper_group` value instead of
    collapsing everything under a single name. Kept here only for
    callers that specifically need "the" wrapper name for a file known
    to have exactly one (e.g. display purposes) — do not use this to
    rebuild a file's XML.
    """
    for d in docs:
        wrapper = (d.get('_wrapper_group') or '').strip()
        if wrapper:
            return wrapper
    return (docs[0].get('group') if docs else '') or 'local'


def decoder_doc_to_xml(doc: dict) -> str:
    """Convert a decoder MongoDB document back to a Wazuh XML string."""
    from services.xml_generator import XMLGenerator
    gen = XMLGenerator()
    raw_xml = gen.generate_decoder(doc)
    return encode_wazuh_xml_fields(raw_xml) # <--- BUNGKUS DI SINI

def rule_doc_to_xml(doc: dict) -> str:
    """Convert a rule MongoDB document back to a Wazuh XML string."""
    from services.xml_generator import XMLGenerator
    gen = XMLGenerator()
    raw_xml = gen.generate_rule(doc)
    return encode_wazuh_xml_fields(raw_xml) # <--- BUNGKUS DI SINI

def decoder_docs_to_xml_file(docs: list[dict]) -> str:
    """Wrap multiple decoder docs into a <decoder_list> XML file string."""
    from services.xml_generator import XMLGenerator
    gen = XMLGenerator()
    raw_xml = gen.generate_decoder_file(docs)
    return encode_wazuh_xml_fields(raw_xml) # <--- BUNGKUS DI SINI

def rule_docs_to_xml_file(group_name: str, docs: list[dict]) -> str:
    """Wrap multiple rule docs into a single <group name="..."> XML file string."""
    from services.xml_generator import XMLGenerator
    gen = XMLGenerator()
    raw_xml = gen.generate_rule_file(group_name, docs)
    return encode_wazuh_xml_fields(raw_xml) # <--- BUNGKUS DI SINI


def _rule_wrapper_of(doc: dict) -> str:
    """Per-rule wrapper name: `_wrapper_group` if this rule carries it
    (set at parse time — see `_wrapper_group_name`, or by the Rule
    Builder's "Nama wrapper" field), else fall back to the rule's own
    `group` field, else 'local'."""
    wrapper = (doc.get('_wrapper_group') or '').strip()
    if wrapper:
        return wrapper
    return (doc.get('group') or '').strip() or 'local'


def build_rule_file_xml(docs: list[dict]) -> str:
    """
    Rebuild a rule file's XML from MongoDB documents, correctly grouping
    rules that span MULTIPLE distinct `_wrapper_group` values into their
    own separate <group name="..."> blocks (see `_rule_wrapper_of`)
    instead of collapsing everything under one name.

    NOTE on well-formedness: concatenating multiple top-level <group>
    blocks like this is NOT well-formed XML per generic parsers/rules
    (a document must have exactly one root element — verified with
    lxml). However, this does NOT mean it's unsafe to push to Wazuh:
    empirically, the Wazuh Manager REST API accepted a small multi-group
    file pushed this exact way without complaint. A separate, much
    larger multi-group file DID fail on push with a generic "XML syntax
    error" from Wazuh, but that failure is NOT reproducible by having
    multiple wrappers alone — the actual cause is still unconfirmed
    (possibly size, possibly specific content). Do not treat "more than
    one wrapper" as a reason to block a push based on this function's
    output; that was tried and disproven.

    Order of blocks follows first-appearance order of each wrapper name
    among `docs`. A file with only one distinct wrapper (the common
    case) produces output identical to calling `rule_docs_to_xml_file`
    directly.
    """
    order: list[str] = []
    buckets: dict[str, list[dict]] = {}
    for doc in docs:
        wrapper = _rule_wrapper_of(doc)
        if wrapper not in buckets:
            buckets[wrapper] = []
            order.append(wrapper)
        buckets[wrapper].append(doc)

    blocks = [rule_docs_to_xml_file(wrapper, buckets[wrapper]) for wrapper in order]
    # Defensive strip: a per-group block should never carry its own XML
    # declaration, but guard against it anyway so concatenating several
    # blocks into one file can never produce more than one <?xml ...?>.
    blocks = [re.sub(r'^\s*<\?xml[^?]*\?>\s*', '', b) for b in blocks]
    return '\n\n'.join(blocks)