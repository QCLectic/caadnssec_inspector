"""
Unit tests for dns_inspector.records.CAARecord and eligibility evaluation.

Run with: pytest tests/test_records.py
"""

from dns_inspector.records import CAARecord
from dns_inspector.compliance import evaluate_caa_eligibility


class TestCAARecord:
    def test_substring_match_rejected(self):
        rec = CAARecord(0, 'issue', 'notssl.com')
        eligible, _ = evaluate_caa_eligibility([rec])
        assert eligible is False

    def test_exact_match_eligible(self):
        rec = CAARecord(0, 'issue', 'ssl.com')
        eligible, _ = evaluate_caa_eligibility([rec])
        assert eligible is True

    def test_params_ignored_case_insensitive(self):
        rec = CAARecord(0, 'issue', 'SSL.COM; account=123')
        eligible, _ = evaluate_caa_eligibility([rec])
        assert eligible is True

    def test_deny_all_semicolon(self):
        rec = CAARecord(0, 'issue', ';')
        assert rec.issuer_domain() == ''
        eligible, _ = evaluate_caa_eligibility([rec])
        assert eligible is False

    def test_critical_unknown_denies(self):
        rec = CAARecord(128, 'futuretag', 'x')
        assert rec.is_critical_unknown is True
        eligible, _ = evaluate_caa_eligibility([rec])
        assert eligible is False

    def test_issuewild_takes_precedence_for_wildcard(self):
        issuewild = CAARecord(0, 'issuewild', 'other.com')
        issue = CAARecord(0, 'issue', 'ssl.com')
        eligible, _ = evaluate_caa_eligibility([issuewild, issue], wildcard=True)
        assert eligible is False

    def test_empty_record_list_eligible(self):
        eligible, _ = evaluate_caa_eligibility([])
        assert eligible is True
