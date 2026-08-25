"""
Unit tests for RecordFormatter.

Run with: pytest tests/test_formatter.py
"""

import pytest
from dns_inspector.formatter import RecordFormatter


class TestRecordFormatter:
    def test_sanitize_removes_script_tags(self):
        val = '<script>alert(1)</script>'
        result = RecordFormatter.sanitize_value(val)
        assert '<script>' not in result
        assert 'alert' not in result or '&lt;' in result

    def test_sanitize_html_escape(self):
        val = '<b>bold</b>'
        result = RecordFormatter.sanitize_value(val)
        assert '<b>' not in result
        assert '&lt;b&gt;' in result

    def test_format_caa_no_records(self):
        text, malicious, ssl_com = RecordFormatter.format_caa_records('No CAA records found')
        assert 'No CAA records found' in text
        assert malicious is False
        assert ssl_com is True

    def test_format_caa_ssl_com(self):
        record = '0 issue "ssl.com"'
        text, malicious, ssl_com = RecordFormatter.format_caa_records(record)
        assert ssl_com is True
        assert malicious is False

    def test_format_caa_other_ca(self):
        record = '0 issue "letsencrypt.org"'
        text, malicious, ssl_com = RecordFormatter.format_caa_records(record)
        assert ssl_com is False

    def test_format_caa_case_insensitive(self):
        """Bug #3: CAA tags must be matched case-insensitively."""
        record = '0 ISSUE "ssl.com"'
        text, malicious, ssl_com = RecordFormatter.format_caa_records(record)
        # After Bug #3 fix: ssl_com should be True for uppercase ISSUE tag
        # Currently this may fail — documents expected behaviour
        assert ssl_com is True, "Uppercase ISSUE tag not recognised (Bug #3 not yet fixed)"

    def test_format_caa_deny_all_semicolon(self):
        """Bug #6: issue \";\" must be treated as deny-all."""
        record = '0 issue ";"'
        text, malicious, ssl_com = RecordFormatter.format_caa_records(record)
        # After Bug #6 fix: ssl_com should be False (deny-all)
        assert ssl_com is False, "Empty issue value ';' not treated as deny-all (Bug #6 not yet fixed)"

    def test_deep_decode_url_encoded(self):
        encoded = 'hello%20world'
        result = RecordFormatter.deep_decode(encoded)
        assert result == 'hello world'

    def test_format_ip_records_both(self):
        result = RecordFormatter.format_ip_records('1.2.3.4', '::1')
        assert 'IPv4' in result
        assert 'IPv6' in result

    def test_format_ip_records_ipv4_only(self):
        result = RecordFormatter.format_ip_records('1.2.3.4', 'No AAAA records found')
        assert 'IPv4' in result
        assert 'IPv6' not in result
