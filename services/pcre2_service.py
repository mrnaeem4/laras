import re


class PCRE2Service:
    """
    Provides PCRE2 pattern validation and matching.
    Python's `re` module implements a PCRE-compatible syntax for the
    subset of features used in Wazuh rules/decoders.
    """

    # Static fields recognised by the Wazuh decoder order option
    STATIC_ORDER_FIELDS = [
        'srcuser', 'dstuser', 'user', 'srcip', 'dstip',
        'srcport', 'dstport', 'protocol', 'system_name',
        'id', 'url', 'action', 'status', 'data', 'extra_data'
    ]

    def validate_pattern(self, pattern: str) -> tuple[bool, str | None]:
        """Validate regex/PCRE2 pattern syntax."""
        if not pattern:
            return False, 'Pattern is empty.'
        try:
            re.compile(pattern)
            return True, None
        except re.error as e:
            return False, str(e)

    def test_pattern(self, pattern: str, log: str) -> tuple[bool, list, dict]:
        """
        Test a PCRE2 pattern against a log string.

        Returns:
            (match_found, all_matches, named_groups_dict)
        """
        try:
            compiled = re.compile(pattern)
            all_matches = compiled.findall(log)
            match_found = bool(all_matches)

            # Extract named groups from the first full match
            extracted = {}
            if compiled.groupindex:
                m = compiled.search(log)
                if m:
                    extracted = {k: v for k, v in m.groupdict().items() if v is not None}

            # Normalise findall result to list of strings
            normalised = []
            for m in all_matches:
                if isinstance(m, tuple):
                    normalised.append(list(m))
                else:
                    normalised.append(m)

            return match_found, normalised, extracted

        except re.error as e:
            return False, [], {'error': str(e)}

    def get_pattern_info(self, pattern: str) -> dict:
        """Return metadata about a regex pattern."""
        valid, error = self.validate_pattern(pattern)
        info = {
            'valid': valid,
            'error': error,
            'length': len(pattern),
            'has_named_groups': bool(re.search(r'\(\?P?<\w+>', pattern)),
            'group_names': []
        }
        if valid:
            try:
                compiled = re.compile(pattern)
                info['group_names'] = list(compiled.groupindex.keys())
                info['group_count'] = compiled.groups
            except re.error:
                pass
        return info

    def escape_for_wazuh(self, text: str) -> str:
        """
        Escape special regex characters so a literal string
        can be safely used inside a Wazuh rule/decoder pattern.
        """
        return re.escape(text)

    def highlight_matches(self, pattern: str, log: str) -> list[dict]:
        """
        Return a list of match spans with start/end positions
        for UI highlighting purposes.
        """
        try:
            compiled = re.compile(pattern)
            return [
                {'start': m.start(), 'end': m.end(), 'text': m.group()}
                for m in compiled.finditer(log)
            ]
        except re.error:
            return []
