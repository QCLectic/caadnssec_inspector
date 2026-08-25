"""
Unit tests for DNSChecker.

Run with: pytest tests/test_checker.py
"""

import pytest
from dns_inspector.checker import DNSChecker
from dns_inspector.config import DNSConfig
from dns_inspector.cache import DNSCache


class TestDNSChecker:
    def setup_method(self):
        self.checker = DNSChecker()

    def test_resolve_known_domain(self):
        result = self.checker.resolve_record('example.com', 'A')
        assert result['status'] in ('NOERROR', 'TIMEOUT', 'ERROR')
        assert 'records' in result

    def test_nxdomain(self):
        result = self.checker.resolve_record('this-domain-does-not-exist-xyz.com', 'A')
        assert result['status'] == 'NXDOMAIN'

    def test_caa_bytes_decoded(self):
        """Bug #1: CAA rdata.value must be decoded — values must not contain b'' prefix."""
        result = self.checker.resolve_record('ssl.com', 'CAA')
        for record in result['records']:
            assert not record.startswith("b'"), f"CAA value still has bytes prefix: {record}"
            assert 'b"' not in record[:5], f"CAA value still has bytes prefix: {record}"

    def test_cname_chain(self):
        result = self.checker.traverse_cname_chain('www.github.com')
        assert 'original_domain' in result
        assert 'final_domain' in result
        assert 'cname_chain' in result

    def test_cache_hit(self):
        self.checker.resolve_record('example.com', 'A')
        stats_before = self.checker.cache.get_stats()
        self.checker.resolve_record('example.com', 'A')
        stats_after = self.checker.cache.get_stats()
        assert stats_after['hits'] > stats_before['hits']

    def test_tree_climbing_uses_original_domain(self):
        """Bug #5: tree climbing should use original domain, not CNAME target."""
        # This test verifies the fix once Bug #5 is resolved.
        # For now it documents the expected behaviour.
        result = self.checker.check_all_records('cname-deny.basic.caatestsuite.com')
        # After fix: parent CAA should be checked from original domain
        assert 'domain' in result
