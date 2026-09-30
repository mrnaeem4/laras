import lxml.etree as etree

from services.wazuh_contract import STATIC_FIELDS, element_for


def _text(value, default: str = '') -> str:
    """Safely coerce a form/AI-provided value into a trimmed string.

    Only strings and numbers are meaningful as element text. Everything else
    (dict/list/None/bool) yields `default` instead of a Python repr — this
    specifically prevents the "[object Object]" / "{'url': ...}" class of bug
    when a structured value (e.g. a field-scoped match object) reaches the
    generator. See services/ai_utils.py's _normalize_rule_draft for the
    backend normalizer that fixes the draft at the source.
    """
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value).strip()
    return default


def _append_condition(parent, element_name: str, entry, *,
                      supports_type: bool = True, supports_negate: bool = True) -> None:
    """Append a field-condition element (e.g. <url>, <srcip>, <field>).

    `entry` is a dict like {"value": ..., "type": "pcre2", "negate": true}
    (or a bare string). `type` is only set when the element documents it and
    the value is one of the allowed regex types; `negate` only when allowed.
    """
    if isinstance(entry, str):
        value, etype, negate = entry.strip(), '', False
    elif isinstance(entry, dict):
        value = _text(entry.get('value'))
        etype = _text(entry.get('type'))
        negate = bool(entry.get('negate'))
    else:
        return
    if not value:
        return
    el = etree.SubElement(parent, element_name)
    el.text = value
    if supports_type and etype in ('osregex', 'osmatch', 'pcre2'):
        el.set('type', etype)
    if supports_negate and negate:
        el.set('negate', 'yes')


class XMLGenerator:
    """
    Generates Wazuh-compliant XML for rules and decoders.

    References:
      - Decoders: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html
      - Rules:    https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
    """

    # ------------------------------------------------------------------ #
    #  DECODER                                                             #
    # ------------------------------------------------------------------ #

    def generate_decoder(self, data: dict) -> str:
        """
        Generate a single <decoder> element wrapped in <decoder_list>.

        Expected data keys:
          name         (str, required) - decoder name attribute
          parent       (str, optional) - <parent> child element
          program_name (str, optional) - <program_name> child element
          program_name_type (str, optional) - type attr: osregex | pcre2 | osmatch
          prematch     (str, optional) - <prematch> child element
          prematch_type (str, optional) - type attr: osregex | pcre2
          prematch_offset (str, optional) - after_regex | after_parent
          regex        (str, optional) - <regex> child element
          regex_type   (str, optional) - type attr: osregex | pcre2
          regex_offset (str, optional) - after_regex | after_parent | after_prematch
          order        (str, optional) - <order> child element
          fts          (str, optional) - <fts> child element
          ftscomment   (str, optional) - <ftscomment> child element
          accumulate   (bool, optional) - adds <accumulate /> tag
          use_own_name (bool, optional) - adds <use_own_name>true</use_own_name>
          type         (str, optional) - <type> child element:
                         syslog | firewall | ids | web-log | squid | windows |
                         host-information | ossec
        """
        name = _text(data.get('name'))
        if not name:
            raise ValueError('Decoder name is required.')

        decoder = etree.Element('decoder', name=name)

        # <parent> — child element, NOT attribute
        if _text(data.get('parent')):
            parent_el = etree.SubElement(decoder, 'parent')
            parent_el.text = _text(data['parent'])

        # <accumulate />
        if data.get('accumulate'):
            etree.SubElement(decoder, 'accumulate')

        # <use_own_name>
        if data.get('use_own_name'):
            uon = etree.SubElement(decoder, 'use_own_name')
            uon.text = 'true'

        # <type>
        if _text(data.get('type')):
            type_el = etree.SubElement(decoder, 'type')
            type_el.text = _text(data['type'])

        # <program_name>
        if _text(data.get('program_name')):
            pn = etree.SubElement(decoder, 'program_name')
            pn.text = _text(data['program_name'])
            if _text(data.get('program_name_type')) in ('osregex', 'pcre2', 'osmatch'):
                pn.set('type', _text(data['program_name_type']))

        # <prematch>
        if _text(data.get('prematch')):
            pm = etree.SubElement(decoder, 'prematch')
            pm.text = _text(data['prematch'])
            if _text(data.get('prematch_type')) in ('osregex', 'pcre2'):
                pm.set('type', _text(data['prematch_type']))
            if _text(data.get('prematch_offset')) in ('after_regex', 'after_parent'):
                pm.set('offset', _text(data['prematch_offset']))

        # <regex>
        if _text(data.get('regex')):
            rx = etree.SubElement(decoder, 'regex')
            rx.text = _text(data['regex'])
            if _text(data.get('regex_type')) in ('osregex', 'pcre2'):
                rx.set('type', _text(data['regex_type']))
            if _text(data.get('regex_offset')) in ('after_regex', 'after_parent', 'after_prematch'):
                rx.set('offset', _text(data['regex_offset']))

        # <order> — required when <regex> is present
        if _text(data.get('order')):
            order_el = etree.SubElement(decoder, 'order')
            order_el.text = _text(data['order'])

        # <fts>
        if _text(data.get('fts')):
            fts_el = etree.SubElement(decoder, 'fts')
            fts_el.text = _text(data['fts'])

        # <ftscomment>
        if _text(data.get('ftscomment')):
            fts_comment = etree.SubElement(decoder, 'ftscomment')
            fts_comment.text = _text(data['ftscomment'])

        return etree.tostring(decoder, encoding='unicode', pretty_print=True)

    def generate_decoder_file(self, decoders: list) -> str:
        """
        Concatenate multiple <decoder> elements with NO enclosing root tag.

        Per official Wazuh syntax (ruleset-xml-syntax/decoders.html) and
        every real decoder file Wazuh ships (e.g. etc/local_decoder.xml),
        <decoder> IS the root element of a decoder file — there is no
        <decoder_list> wrapper. Multiple decoders in one file are simply
        placed one after another. Wrapping them in <decoder_list> (as this
        function previously did) produces a tag Wazuh's own ruleset never
        uses and was the cause of decoders showing/pushing incorrectly.

        This mirrors how build_rule_file_xml() in xml_parser.py already
        concatenates multiple top-level <group> blocks for rules without
        an outer wrapper — same non-single-root-but-Wazuh-accepts-it
        pattern, just with no wrapper element at all instead of per-group
        wrappers, since decoders have nothing analogous to `_wrapper_group`.
        """
        blocks = [self.generate_decoder(d).rstrip() for d in decoders]
        return '\n\n'.join(blocks)

    # ------------------------------------------------------------------ #
    #  RULE                                                                #
    # ------------------------------------------------------------------ #

    def generate_rule(self, data: dict) -> str:
        """
        Generate a single <rule> element.

        Expected data keys:
          rule_id           (str/int, required) - rule id attribute (1-999999)
          level        (str/int, required) - rule level attribute (0-16)
          description  (str, required)     - <description> child element
          info         (str/list, optional)- <info> element(s); each entry:
                                             { value, type } or a plain string
          info_type    (str, optional)     - type attr for single info string

          # Conditions / parent matching
          if_sid            (str, optional) - <if_sid> list of IDs
          if_group          (str, optional) - <if_group> group name
          if_level          (str, optional) - <if_level>
          if_matched_sid    (str, optional) - <if_matched_sid> — used with
                                              frequency rules (correlation)
          if_matched_group  (str, optional) - <if_matched_group>

          # Match conditions
          match        (str, optional)     - <match> text/sregex
          match_type   (str, optional)     - osmatch | osregex | pcre2
          match_negate (bool, optional)    - negate="yes"
          regex        (str, optional)     - <regex> expression
          regex_type   (str, optional)     - osregex | osmatch | pcre2
          decoded_as   (str, optional)     - <decoded_as> decoder name

          # URL conditions (list of dicts)
          urls: [
            { value: str, type: 'osregex'|'pcre2'|'osmatch', negate: bool }
          ]

          # Field conditions (list of dicts)
          fields: [
            { name: str, value: str, type: 'osregex'|'pcre2'|'osmatch', negate: bool }
          ]

          # Threat intel / list lookup
          lists: [
            { field: str, lookup: str, path: str }
          ]
          e.g. { field: "srcip", lookup: "address_match_key",
                 path: "etc/lists/ultimate-ipsets" }

          # Time window
          time         (str, optional)     - <time> e.g. "10 pm - 5 am"

          # Correlation / frequency helpers
          same_srcip      (bool, optional) - adds <same_srcip />
          different_srcip (bool, optional) - adds <different_srcip />
          same_url        (bool, optional) - adds <same_url />
          same_fields     (list, optional) - list of field names for <same_field>
                                             e.g. ["user_agent", "domain"]

          # Taxonomy
          group        (str, optional)     - <group> comma-separated groups
          mitre_ids    (list, optional)    - list of MITRE ATT&CK IDs

          # Rule attributes
          frequency    (str, optional)     - frequency attribute
          timeframe    (str, optional)     - timeframe attribute
          ignore       (str, optional)     - ignore attribute
          overwrite    (str, optional)     - overwrite attribute (yes/no)
          noalert      (str, optional)     - noalert attribute (0/1)

          # Options
          options      (list, optional)    - list of option strings
        """
        # 'rule_id' is the canonical key (matches the MongoDB `rules` collection),
        # but accept 'id' too since some callers (e.g. raw frontend form payloads
        # in builder.py) may still send it under that name.
        rule_id = str(data.get('rule_id') or data.get('id') or '').strip()
        level_raw = data.get('level')
        level = str(level_raw).strip() if level_raw is not None else '0'

        if not rule_id:
            raise ValueError('Rule id is required.')

        attrs = {'id': rule_id, 'level': level}

        # Optional rule-level attributes.
        # [FIX 24 Agustus 2026] data.get(attr, '') hanya pakai default ''
        # kalau key-nya BENAR-BENAR TIDAK ADA. Snapshot dari history
        # (lihat services/history_utils.py _snapshot()) selalu punya
        # semua field ini sebagai key, dengan value None kalau memang
        # belum pernah diisi — jadi .get(attr, '') balikin None apa
        # adanya (bukan ''), lalu str(None) jadi string "None" yang lolos
        # cek `if val:` karena non-empty. Cek None secara eksplisit dulu
        # sebelum str() supaya baik key-absen (payload form biasa) maupun
        # key-ada-tapi-None (snapshot history/rollback) sama-sama di-skip.
        for attr in ('frequency', 'timeframe', 'ignore', 'overwrite', 'noalert', 'maxsize'):
            raw_val = data.get(attr)
            if raw_val is None:
                continue
            # _text() (bukan str()) supaya nilai terstruktur (dict/list) tidak
            # ikut ter-render sebagai repr Python ke atribut XML.
            val = _text(raw_val)
            if val:
                attrs[attr] = val

        rule = etree.Element('rule', **attrs)

        # <description>  (always include)
        description_text = _text(data.get('description'))
        if description_text:
            desc_el = etree.SubElement(rule, 'description')
            desc_el.text = description_text

        # <info> — supports multiple entries as a list of dicts OR a single string
        info_entries = data.get('info', '')
        if isinstance(info_entries, list):
            for entry in info_entries:
                if isinstance(entry, dict):
                    val = _text(entry.get('value'))
                    itype = _text(entry.get('type'))
                else:
                    val = str(entry).strip()
                    itype = ''
                if val:
                    info_el = etree.SubElement(rule, 'info')
                    info_el.text = val
                    if itype in ('text', 'link', 'cve', 'ovsdb'):
                        info_el.set('type', itype)
        elif isinstance(info_entries, str) and info_entries.strip():
            info_el = etree.SubElement(rule, 'info')
            info_el.text = info_entries.strip()
            info_type = _text(data.get('info_type'))
            if info_type in ('text', 'link', 'cve', 'ovsdb'):
                info_el.set('type', info_type)

        # <decoded_as>
        if _text(data.get('decoded_as')):
            da = etree.SubElement(rule, 'decoded_as')
            da.text = _text(data['decoded_as'])

        # <if_sid>
        if _text(data.get('if_sid')):
            if_sid_el = etree.SubElement(rule, 'if_sid')
            if_sid_el.text = _text(data['if_sid'])

        # <if_group>
        if _text(data.get('if_group')):
            if_group_el = etree.SubElement(rule, 'if_group')
            if_group_el.text = _text(data['if_group'])

        # <if_level>
        if _text(data.get('if_level')):
            if_level_el = etree.SubElement(rule, 'if_level')
            if_level_el.text = _text(data['if_level'])

        # <if_matched_sid>  — for frequency/correlation rules
        if _text(data.get('if_matched_sid')):
            im_sid = etree.SubElement(rule, 'if_matched_sid')
            im_sid.text = _text(data['if_matched_sid'])

        # <if_matched_group>
        if _text(data.get('if_matched_group')):
            im_grp = etree.SubElement(rule, 'if_matched_group')
            im_grp.text = _text(data['if_matched_group'])

        # <match>
        if _text(data.get('match')):
            match_el = etree.SubElement(rule, 'match')
            match_el.text = _text(data['match'])
            match_type = _text(data.get('match_type'))
            if match_type in ('osmatch', 'osregex', 'pcre2'):
                match_el.set('type', match_type)
            if data.get('match_negate'):
                match_el.set('negate', 'yes')

        # <regex>
        if _text(data.get('regex')):
            regex_el = etree.SubElement(rule, 'regex')
            regex_el.text = _text(data['regex'])
            regex_type = _text(data.get('regex_type'))
            if regex_type in ('osregex', 'osmatch', 'pcre2'):
                regex_el.set('type', regex_type)

        # <url> conditions — list of dicts. `url` is a STATIC field with its
        # own dedicated element (see services/wazuh_contract.py).
        for url_entry in data.get('urls', []):
            _append_condition(rule, 'url', url_entry)

        # Generic STATIC-field conditions: {"srcip": [{value,type,negate}], ...}.
        # Iterated in the contract's canonical order (not the dict's insertion
        # order) so regenerating a parsed document yields byte-identical XML —
        # keeps diffs clean across a pull/push round-trip.
        static_fields = data.get('static_fields') or {}
        if isinstance(static_fields, dict):
            for fname in STATIC_FIELDS:
                if fname not in static_fields:
                    continue
                if fname == 'url':
                    # url has its own `urls` list; skip here to avoid
                    # double-rendering if a payload sets both.
                    continue
                info = element_for(fname)
                if not info:
                    continue
                element_name, supports_type, supports_negate = info
                entries = static_fields[fname]
                if not isinstance(entries, list):
                    entries = [entries]
                for entry in entries:
                    _append_condition(
                        rule, element_name, entry,
                        supports_type=supports_type, supports_negate=supports_negate,
                    )

        # <field name="..."> conditions — DYNAMIC fields from a decoder's
        # <order>. Static field names here are rejected in favour of their
        # dedicated element so we never emit <field name="url">.
        for field in data.get('fields', []):
            fname = _text(field.get('name'))
            if not fname:
                continue
            info = element_for(fname)
            if info and info[0] != 'url':
                # Misplaced static field -> render its proper element instead.
                _append_condition(
                    rule, info[0], field,
                    supports_type=info[1], supports_negate=info[2],
                )
                continue
            if fname.lower() == 'url':
                _append_condition(rule, 'url', field)
                continue
            fvalue = _text(field.get('value'))
            if fvalue:
                field_el = etree.SubElement(rule, 'field', name=fname)
                field_el.text = fvalue
                ftype = _text(field.get('type'))
                if ftype in ('osregex', 'osmatch', 'pcre2'):
                    field_el.set('type', ftype)
                if field.get('negate'):
                    field_el.set('negate', 'yes')

        # <list field="..." lookup="...">path</list>  — threat intel / IP lists
        for lst in data.get('lists', []):
            lfield  = _text(lst.get('field'))
            llookup = _text(lst.get('lookup'))
            lpath   = _text(lst.get('path'))
            if lfield and lpath:
                list_el = etree.SubElement(rule, 'list', field=lfield)
                list_el.text = lpath
                if llookup:
                    list_el.set('lookup', llookup)

        # <time>  — time-window matching
        if _text(data.get('time')):
            time_el = etree.SubElement(rule, 'time')
            time_el.text = _text(data['time'])

        # Correlation helpers (self-closing elements)
        if data.get('same_srcip'):
            etree.SubElement(rule, 'same_srcip')

        if data.get('different_srcip'):
            etree.SubElement(rule, 'different_srcip')

        if data.get('same_url'):
            etree.SubElement(rule, 'same_url')

        # <same_field> — one element per field name
        for sf in data.get('same_fields', []):
            sf = sf.strip() if isinstance(sf, str) else ''
            if sf:
                sf_el = etree.SubElement(rule, 'same_field')
                sf_el.text = sf

        # <group>
        if _text(data.get('group')):
            group_el = etree.SubElement(rule, 'group')
            group_text = _text(data['group'])
            if not group_text.endswith(','):
                group_text += ','
            group_el.text = group_text

        # <mitre>
        mitre_ids = data.get('mitre_ids', [])
        if isinstance(mitre_ids, str):
            mitre_ids = [m.strip() for m in mitre_ids.split(',') if m.strip()]
        if mitre_ids:
            mitre_el = etree.SubElement(rule, 'mitre')
            for mid in mitre_ids:
                mid_el = etree.SubElement(mitre_el, 'id')
                mid_el.text = mid.strip()

        # <options>
        for opt in data.get('options', []):
            opt_el = etree.SubElement(rule, 'options')
            opt_el.text = opt.strip()

        return etree.tostring(rule, encoding='unicode', pretty_print=True)

    def generate_rule_file(self, group_name: str, rules: list) -> str:
        """Wrap multiple rules in a <group name="..."> root element."""
        group_name = group_name.strip()
        if not group_name.endswith(','):
            group_name += ','
        root = etree.Element('group', name=group_name)
        for r in rules:
            xml_str = self.generate_rule(r)
            rule_el = etree.fromstring(xml_str)
            root.append(rule_el)
        return etree.tostring(root, encoding='unicode', pretty_print=True,
                              xml_declaration=False)