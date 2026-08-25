# CAA DNSSEC Inspector — Project Manifest & Migration Plan
**File:** `CAA_DNSSEC_Inspector.ipynb`  
**Status:** Active — bugs identified, caatestsuite.com integration pending  
**Next Target:** Claude Code project

---

## Architecture Overview

The notebook is organized as a class-based pipeline across 11 cells:

| Cell | Class / Function | Role |
|---|---|---|
| 1 | — | pip install |
| 2 | — | Imports |
| 3 | `DNSConfig` | Central config: timeouts, nameservers, record types |
| 4 | `DNSCache` | In-memory cache with hit/miss stats |
| 5 | `DNSChecker` | Core DNS logic: resolve, DNSSEC, CNAME chain, parent CAA |
| 6 | `RecordFormatter` | Sanitize/parse/format records for display |
| 7 | `DataFrameStyler` | Pandas DataFrame prep + color-coded HTML styling |
| 8 | `UIUtils` | CSV/HTML download link generation |
| 9 | `UIComponents` | Filter widgets, collapsible sections, responsive view |
| 10 | `run_dns_checks()` | Orchestrates domain batch processing with tqdm |
| 11 | `setup_enhanced_ui()` | Wires up widgets and launches the UI |

---

## 🐛 Bugs Found

### 1. `rdata.value` Returns Bytes — CAA Values Are Broken (HIGH)
**Location:** `DNSChecker.resolve_record()` → CAA branch  
**Problem:** In dnspython, `CAA.value` is a `bytes` object, not a string. This means CAA records render as:
```
0 issue "b'ssl.com'"
```
...instead of `0 issue "ssl.com"`. The `RecordFormatter` has hacky regex (`re.sub(r'b[\'\"]...`)  to strip the `b'` prefix — this is the workaround, not the fix.  
**Fix:**
```python
# In resolve_record(), CAA branch:
f"{rdata.flags} {rdata.tag} \"{rdata.value.decode('utf-8')}\""
```

---

### 2. DNSSEC `validator_resolver.dnssec = True` Does Nothing (HIGH)
**Location:** `DNSChecker.check_dnssec()`  
**Problem:** `dns.resolver.Resolver` has no `.dnssec` attribute. Setting it to `True` is silently ignored — DNSSEC validation is **not actually being performed**. The tool only checks whether DNSKEY records *exist*, not whether the chain validates.  
**Fix:** Use `dns.resolver.Resolver().use_edns(0, dns.flags.DO, 4096)` or perform validation manually via `dns.dnssec.validate()`.

---

### 3. CAA Tag Case Sensitivity Not Handled (MEDIUM)
**Location:** `check_ssl_com_issuance_eligibility()` and `RecordFormatter.format_caa_records()`  
**Problem:** CAA tags must be matched case-insensitively per RFC 8659. The regex `r'(issue|issuewild)'` fails for `0 ISSUE "ssl.com"` or `0 IsSuE "ssl.com"`.  
**caatestsuite.com tests:** `uppercase-deny.basic.caatestsuite.com`, `mixedcase-deny.basic.caatestsuite.com`  
**Fix:** Add `re.IGNORECASE` flag consistently.

---

### 4. Critical Flag Unknown Property Not Handled (MEDIUM)
**Location:** `DNSChecker.resolve_record()` / eligibility logic  
**Problem:** If a CAA record has flag bit 7 set (value ≥ 128) with an **unknown** property tag, the CA **must refuse to issue**. The notebook ignores the critical flag entirely.  
**caatestsuite.com tests:** `critical1.basic.caatestsuite.com` (`128 caatestsuitedummyproperty "test"`), `critical2.basic.caatestsuite.com`  
**Fix:** Parse the flag integer; if `flags >= 128` and the tag is not `issue`/`issuewild`/`iodef`, mark as ineligible with reason `"Unknown critical CAA property"`.

---

### 5. CAA Tree Climbing Uses CNAME Target, Not Original Domain (MEDIUM)
**Location:** `DNSChecker.check_all_records()`  
**Problem:** `check_parent_caa_records(check_domain)` is called with the **final CNAME target** instead of the original domain. Per RFC 8659, CAA tree climbing should start from the **original requested domain**, not the CNAME target.  
**caatestsuite.com tests:** `cname-deny.basic.caatestsuite.com`, `sub1.cname-deny.basic.caatestsuite.com`  
**Fix:** Pass `domain` (original) instead of `check_domain` to `check_parent_caa_records()`.

---

### 6. Empty Issue Value `";"` Not Handled (MEDIUM)
**Location:** `check_ssl_com_issuance_eligibility()` / CAA parsing  
**Problem:** `0 issue ";"` means **no CA is allowed to issue** (explicit deny-all). The current parser would find no `ssl.com` match and return "no restrictions" rather than flagging it as a hard deny.  
**caatestsuite.com test:** `empty.basic.caatestsuite.com`  
**Fix:** Check for `issue ";"` explicitly and return `(False, "CAA issue record explicitly denies all issuance")`.

---

### 7. XSS Test Not Fully Covered (LOW)
**Location:** `RecordFormatter.sanitize_value()`  
**Problem:** The sanitizer catches basic `<script>` and `onerror` patterns, but the caatestsuite XSS test (`xss.caatestsuite.com`) may contain more sophisticated payloads. The current approach of string-matching for `script` and `alert` is fragile.  
**caatestsuite.com test:** `xss.caatestsuite.com`  
**Fix:** Rely entirely on `html.escape()` (already called) — strip the manual pattern matching and trust HTML escaping.

---

## caatestsuite.com Integration Plan

Add a **"Run CAA Compliance Tests"** button that batch-checks all test suite FQDNs and verifies the expected behavior.

### Deny Tests (all should return `ssl_com_eligible = No`)
```
empty.basic.caatestsuite.com
deny.basic.caatestsuite.com
uppercase-deny.basic.caatestsuite.com
mixedcase-deny.basic.caatestsuite.com
big.basic.caatestsuite.com
critical1.basic.caatestsuite.com
critical2.basic.caatestsuite.com
sub1.deny.basic.caatestsuite.com
sub2.sub1.deny.basic.caatestsuite.com
*.deny.basic.caatestsuite.com
*.deny-wild.basic.caatestsuite.com
cname-deny.basic.caatestsuite.com
cname-cname-deny.basic.caatestsuite.com
sub1.cname-deny.basic.caatestsuite.com
deny.permit.basic.caatestsuite.com
ipv6only.caatestsuite.com
expired.caatestsuite-dnssec.com
missing.caatestsuite-dnssec.com
blackhole.caatestsuite-dnssec.com
servfail.caatestsuite-dnssec.com
refused.caatestsuite-dnssec.com
xss.caatestsuite.com
```

### Compliance Test Runner Concept
```python
CAA_TEST_SUITE = {
    # (fqdn, expected_eligible, description)
    ("empty.basic.caatestsuite.com",        False, "issue ';' deny-all"),
    ("deny.basic.caatestsuite.com",         False, "basic deny"),
    ("uppercase-deny.basic.caatestsuite.com", False, "uppercase ISSUE tag"),
    ("mixedcase-deny.basic.caatestsuite.com", False, "mixedcase IsSuE tag"),
    ("critical1.basic.caatestsuite.com",    False, "unknown critical property"),
    ("critical2.basic.caatestsuite.com",    False, "unknown critical property alt flag"),
    ("sub1.deny.basic.caatestsuite.com",    False, "tree climbing parent"),
    ("cname-deny.basic.caatestsuite.com",   False, "CNAME CAA at target"),
    ...
}

def run_compliance_tests():
    results = []
    for fqdn, expected, desc in CAA_TEST_SUITE:
        result = checker.check_all_records(fqdn)
        eligible = result.get('ssl_com_eligible') == 'Yes'
        passed = eligible == expected
        results.append({
            'fqdn': fqdn,
            'description': desc,
            'expected': 'Eligible' if expected else 'Denied',
            'actual': 'Eligible' if eligible else 'Denied',
            'passed': '✅' if passed else '❌'
        })
    return pd.DataFrame(results)
```

---

## Moving to Claude Code — Recommendations

### 1. Restructure as a Python Package (not a flat notebook)
```
caa-dnssec-inspector/
├── README.md
├── requirements.txt
├── .env.example
├── dns_inspector/
│   ├── __init__.py
│   ├── config.py          # DNSConfig
│   ├── cache.py           # DNSCache
│   ├── checker.py         # DNSChecker
│   ├── formatter.py       # RecordFormatter
│   ├── compliance.py      # caatestsuite.com test suite runner  ← NEW
│   └── ui/
│       ├── __init__.py
│       ├── styler.py      # DataFrameStyler
│       ├── components.py  # UIComponents
│       └── utils.py       # UIUtils
├── notebooks/
│   └── CAA_DNSSEC_Inspector.ipynb  # thin shell that imports from dns_inspector/
└── tests/
    ├── test_checker.py
    ├── test_formatter.py
    └── test_compliance.py         # caatestsuite.com integration tests
```

### 2. Start Claude Code with a CLAUDE.md file
Create a `CLAUDE.md` at the project root. Claude Code reads this on startup. Include:
- Purpose of the tool
- Key classes and where they live
- Known bugs (copy from this manifest)
- Test commands (`pytest tests/`)
- How to run the notebook

### 3. Fix Bugs in Claude Code Before Refactoring
Give Claude Code these tasks in order:
1. Fix the `rdata.value.decode('utf-8')` bug first — it affects every downstream function
2. Fix critical flag handling
3. Fix CAA case sensitivity
4. Fix tree climbing domain bug
5. Add compliance test runner using caatestsuite.com FQDNs
6. Add pytest test suite that uses caatestsuite.com domains as fixtures

### 4. Use Claude Code's `/test` Command
After each bug fix, run the caatestsuite.com compliance tests as your regression suite. This gives you ground truth — if all 22 deny tests come back `Denied`, the CAA logic is correct.

### 5. Pin Dependencies
```
# requirements.txt
dnspython==2.6.1
pandas==2.2.0
ipywidgets==8.1.2
tqdm==4.66.2
jupyter==1.0.0
pytest==8.0.0
```

### 6. Suggested First Claude Code Prompt
> "I'm working on a DNS CAA/DNSSEC inspection tool. Read CLAUDE.md first, then fix the bugs listed there starting with the rdata.value bytes decode issue in checker.py. After each fix, run the caatestsuite.com compliance tests to verify."

---

## Summary: Priority Fix Order

| Priority | Bug | Impact |
|---|---|---|
| 🔴 1 | `rdata.value` bytes not decoded | CAA values render as `b'ssl.com'` everywhere |
| 🔴 2 | DNSSEC validator no-op | DNSSEC validation silently disabled |
| 🟠 3 | Empty `";"` CAA not handled | False eligibility on deny-all domains |
| 🟠 4 | Critical flag unknown property | Missing compliance requirement |
| 🟠 5 | CAA tag case insensitivity | Fails UPPERCASE/mixedcase test cases |
| 🟡 6 | Tree climbing uses CNAME target | Incorrect parent CAA lookup |
| 🟡 7 | XSS sanitizer fragile | Rely on html.escape() instead |
