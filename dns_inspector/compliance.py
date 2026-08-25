"""
CAA compliance test runner using caatestsuite.com.

Run via: python -m dns_inspector.compliance
Or import run_compliance_tests() and call it directly.
"""

import pandas as pd

from .checker import DNSChecker

# (fqdn, expected_eligible, description)
CAA_TEST_SUITE = [
    ("empty.basic.caatestsuite.com",          False, "issue ';' deny-all"),
    ("deny.basic.caatestsuite.com",           False, "basic deny"),
    ("uppercase-deny.basic.caatestsuite.com", False, "uppercase ISSUE tag"),
    ("mixedcase-deny.basic.caatestsuite.com", False, "mixedcase IsSuE tag"),
    ("big.basic.caatestsuite.com",            False, "large CAA record set"),
    ("critical1.basic.caatestsuite.com",      False, "unknown critical property (flag=128)"),
    ("critical2.basic.caatestsuite.com",      False, "unknown critical property alt flag"),
    ("sub1.deny.basic.caatestsuite.com",      False, "tree climbing: parent deny"),
    ("sub2.sub1.deny.basic.caatestsuite.com", False, "tree climbing: grandparent deny"),
    ("*.deny.basic.caatestsuite.com",         False, "wildcard deny"),
    ("*.deny-wild.basic.caatestsuite.com",    False, "issuewild deny"),
    ("cname-deny.basic.caatestsuite.com",     False, "CNAME target has deny CAA"),
    ("cname-cname-deny.basic.caatestsuite.com", False, "double CNAME target has deny CAA"),
    ("sub1.cname-deny.basic.caatestsuite.com", False, "sub of CNAME deny"),
    ("deny.permit.basic.caatestsuite.com",    False, "deny overrides permit in same zone"),
    ("ipv6only.caatestsuite.com",             False, "IPv6-only nameserver"),
    ("expired.caatestsuite-dnssec.com",       False, "DNSSEC signature expired"),
    ("missing.caatestsuite-dnssec.com",       False, "DNSSEC record missing"),
    ("blackhole.caatestsuite-dnssec.com",     False, "DNSSEC blackhole"),
    ("servfail.caatestsuite-dnssec.com",      False, "SERVFAIL response"),
    ("refused.caatestsuite-dnssec.com",       False, "REFUSED response"),
    ("xss.caatestsuite.com",                  False, "XSS payload in CAA record"),
]


def evaluate_caa_eligibility(caa_records, ca_domain="ssl.com", wildcard=False):
    """Given list[CAARecord] for the relevant zone, return (eligible: bool, reason: str).

    Rules (RFC 8659 section 4):
    - Any critical-flag record with unknown tag -> (False, 'unknown critical CAA property')
    - Select relevant tag set: for wildcard requests use issuewild records if ANY
      issuewild records exist, else fall back to issue records. For non-wildcard
      use issue records only.
    - If relevant set is empty -> (True, 'no relevant CAA restrictions') ONLY when
      there are no issue/issuewild records at all in the zone; if issue records
      exist but none match, it's a deny.
    - Eligible iff any relevant record's issuer_domain() == ca_domain (EXACT match,
      case-insensitive, no substring matching). issuer_domain() == '' is deny-all.
    """
    if any(rec.is_critical_unknown for rec in caa_records):
        return False, 'unknown critical CAA property'

    issue_records = [r for r in caa_records if r.tag == 'issue']
    issuewild_records = [r for r in caa_records if r.tag == 'issuewild']

    if wildcard and issuewild_records:
        relevant = issuewild_records
    else:
        relevant = issue_records

    if not issue_records and not issuewild_records:
        return True, 'no relevant CAA restrictions'

    if not relevant:
        return False, 'CAA records exist but none permit this CA'

    ca_domain = ca_domain.lower()
    for rec in relevant:
        issuer = rec.issuer_domain()
        if issuer == ca_domain:
            return True, f'{rec.tag} permits {ca_domain}'

    return False, 'CAA records exist but none permit this CA'


def _is_eligible(result: dict) -> bool:
    """Determine ssl.com eligibility from a check_all_records() result."""
    # SERVFAIL / REFUSED / TIMEOUT → must not issue (fail closed)
    dns_status = result.get('dns_status', '')
    if 'SERVFAIL' in dns_status or 'REFUSED' in dns_status or 'TIMEOUT' in dns_status:
        return False

    caa_structured = result.get('caa_structured', [])
    if caa_structured:
        eligible, _ = evaluate_caa_eligibility(caa_structured)
        return eligible

    # No CAA records at this domain → check parent tree
    parent_caa = result.get('parent_caa', {})
    if not parent_caa:
        return True

    parent_records = []
    for parent in parent_caa.values():
        if isinstance(parent, dict):
            parent_records = parent.get('records', [])
        break

    eligible, _ = evaluate_caa_eligibility(parent_records)
    return eligible


def run_compliance_tests(verbose: bool = True) -> pd.DataFrame:
    """
    Run all caatestsuite.com compliance tests and return a results DataFrame.

    Each row contains: fqdn, description, expected, actual, passed.
    """
    checker = DNSChecker()
    rows = []

    for fqdn, expected, desc in CAA_TEST_SUITE:
        if verbose:
            print(f"  Checking {fqdn} …", end=" ", flush=True)
        try:
            result = checker.check_all_records(fqdn)
            eligible = _is_eligible(result)
        except Exception as e:
            eligible = False  # fail closed on error — a CA must not issue on unknown status
            if verbose:
                print(f"ERROR: {e}")

        passed = (eligible == expected)
        if verbose:
            status = "PASS" if passed else "FAIL"
            print(status)

        rows.append({
            'fqdn': fqdn,
            'description': desc,
            'expected': 'Eligible' if expected else 'Denied',
            'actual': 'Eligible' if eligible else 'Denied',
            'passed': passed,
        })

    df = pd.DataFrame(rows)
    total = len(df)
    passed_count = df['passed'].sum()

    if verbose:
        print(f"\nResults: {passed_count}/{total} tests passed")

    return df


if __name__ == '__main__':
    results = run_compliance_tests()
    print(results.to_string(index=False))
