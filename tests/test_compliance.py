"""
caatestsuite.com compliance integration tests.

These tests make live DNS queries — run them only when you have network access
and want to validate CAA logic correctness.

Run with: pytest tests/test_compliance.py -v
Or just the deny tests: pytest tests/test_compliance.py -v -k "deny"
"""

import pytest
import pandas as pd
from dns_inspector.compliance import run_compliance_tests, CAA_TEST_SUITE, _is_eligible
from dns_inspector.checker import DNSChecker


@pytest.mark.integration
def test_all_compliance_tests():
    """Run all caatestsuite.com tests and report failures."""
    results = run_compliance_tests(verbose=False)
    failures = results[~results['passed']]

    if not failures.empty:
        msg = f"\n{len(failures)} compliance test(s) failed:\n" + failures.to_string(index=False)
        pytest.fail(msg)


@pytest.mark.integration
@pytest.mark.parametrize("fqdn,expected,description", CAA_TEST_SUITE)
def test_compliance_case(fqdn, expected, description):
    """Individual parametrized compliance test for each caatestsuite.com FQDN."""
    checker = DNSChecker()
    result = checker.check_all_records(fqdn)
    eligible = _is_eligible(result)
    expected_label = 'Eligible' if expected else 'Denied'
    actual_label = 'Eligible' if eligible else 'Denied'
    assert eligible == expected, (
        f"{fqdn} ({description}): expected {expected_label}, got {actual_label}"
    )
