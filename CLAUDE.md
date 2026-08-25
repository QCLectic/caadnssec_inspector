# CAA DNSSEC Inspector

DNS CAA/DNSSEC inspection tool. Checks CAA records, DNSSEC validation status, and ssl.com
issuance eligibility for a batch of domains. Originally a monolithic Jupyter notebook,
now structured as an importable Python package.

---

## Package Layout

```
dns_inspector/
├── config.py        DNSConfig — timeouts, nameservers, record type list
├── cache.py         DNSCache  — in-memory cache with hit/miss stats
├── checker.py       DNSChecker — core DNS logic (resolve, DNSSEC, CNAME, parent CAA)
├── formatter.py     RecordFormatter — parse/sanitize/format records for display
├── compliance.py    caatestsuite.com compliance runner (CAA_TEST_SUITE + run_compliance_tests)
└── ui/
    ├── styler.py    DataFrameStyler — pandas DataFrame + color-coded HTML styling
    ├── utils.py     UIUtils — CSV/HTML download links, run_dns_checks() batch runner
    └── components.py UIComponents + setup_enhanced_ui() — ipywidgets UI
notebooks/
└── CAA_DNSSEC_Inspector.ipynb  — thin shell, imports from dns_inspector
tests/
├── test_checker.py
├── test_formatter.py
└── test_compliance.py  — live DNS integration tests against caatestsuite.com
```

---

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Open the notebook
jupyter notebook notebooks/CAA_DNSSEC_Inspector.ipynb

# Run unit tests (no network required for most)
pytest tests/test_checker.py tests/test_formatter.py -v

# Run caatestsuite.com compliance integration tests (requires network)
pytest tests/test_compliance.py -v -m integration

# Run compliance tests from the CLI
python -m dns_inspector.compliance
```

---

## Bug Status — All Fixed ✓

### 1. rdata.value bytes decoded ✓
`checker.py` `resolve_record()` CAA branch — `rdata.value.decode('utf-8')`.
Removed hacky `re.sub(r"b['\"]...")` workarounds from `formatter.py`.

### 2. DNSSEC validator real validation ✓
`checker.py` `check_dnssec()` — queries with DO bit via `dns.message.make_query(..., want_dnssec=True)`,
sends to validating resolvers (1.1.1.1, 9.9.9.9), checks AD flag and SERVFAIL response.

### 3. CAA tag case insensitivity ✓
`formatter.py` `format_caa_records()` and `simplify_parent_caa()` — `re.IGNORECASE` on all
`issue`/`issuewild` patterns. Tags normalised to lowercase in output.

### 4. Critical flag unknown property ✓
`checker.py` — `_has_critical_unknown_caa()` static helper parses flags integer; sets
`result['caa_critical_deny'] = True` when `flags >= 128` and tag not in `{issue, issuewild, iodef}`.
`compliance.py` `_is_eligible()` checks this key.

### 5. Tree climbing uses original domain ✓
`checker.py` `check_all_records()` — `check_parent_caa_records(domain)` (original) instead of
`check_parent_caa_records(check_domain)` (CNAME target).

### 6. Empty `";"` CAA deny-all ✓
`formatter.py` `format_caa_records()` — explicit regex match for `issue ";"` returns
`('CAA deny-all: issue ";"', False, False)` before any other processing.
`compliance.py` `_is_eligible()` checks for `deny-all` in CAA string.

### 7. XSS sanitizer relies on html.escape() ✓
`formatter.py` `sanitize_value()` — fragile pattern matches removed; only `html.escape()` used.

---

## Compliance Test Workflow

After each bug fix, run the compliance tests to confirm the fix and guard against regressions:

```bash
pytest tests/test_compliance.py -v -m integration
```

All 22 deny-test FQDNs in `CAA_TEST_SUITE` must return `Denied` when the logic is correct.

---

## Key Classes

| Class | File | Responsibilities |
|---|---|---|
| `DNSConfig` | `config.py` | Timeouts, nameservers, record types, logging setup |
| `DNSCache` | `cache.py` | In-memory cache keyed by `(domain, record_type)` |
| `DNSChecker` | `checker.py` | `resolve_record()`, `check_dnssec()`, `traverse_cname_chain()`, `check_all_records()` |
| `RecordFormatter` | `formatter.py` | `format_caa_records()`, `sanitize_value()`, various simplify/format helpers |
| `DataFrameStyler` | `ui/styler.py` | `prepare_for_display()`, `apply_styling()`, color-coded pandas Styler |
| `UIUtils` | `ui/utils.py` | Download links (CSV/HTML), `run_dns_checks()` batch runner |
| `UIComponents` | `ui/components.py` | Filter widgets, download options, `setup_enhanced_ui()` |
