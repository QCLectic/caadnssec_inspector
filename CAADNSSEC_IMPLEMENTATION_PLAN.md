# CAA DNSSEC Inspector — Implementation Plan

Repo: https://github.com/QCLectic/caadnssec_inspector

## Goals

1. Batch scans must be fast: target 100 domains in under 30 seconds (quick profile).
2. Output must say what to FIX, not just what the status is (findings + remediation).
3. Correct RFC 8659 eligibility logic (the current substring match is wrong).
4. Usable from the CLI, not just Jupyter.

## Rules for the implementing agent

- Read CLAUDE.md in the repo root before starting.
- Work through phases IN ORDER. Do not start a phase until the previous phase's
  acceptance criteria pass.
- After every phase, run: `pytest tests/test_checker.py tests/test_formatter.py -v`
  All tests must pass before moving on. If a test fails and you cannot fix it within
  the scope of the current phase, STOP and report the failure instead of changing
  the test to pass.
- Do not modify files under `dns_inspector/ui/` except where a phase explicitly says so.
- Do not rewrite whole files when a targeted edit works. Keep diffs small.
- Do not add new dependencies beyond those listed in this plan.
- Never weaken an assertion in an existing test to make it pass.
- Update CLAUDE.md at the end of each phase to reflect what changed.

---

## Phase 0 — Small hygiene fixes (warmup)

All in `dns_inspector/checker.py` unless noted.

1. Remove unused imports: `logging`, `socket`, `dns.dnssec`, `dns.rdataclass`,
   and `TimeoutError` from `concurrent.futures` (keep `ThreadPoolExecutor` —
   Phase 3 uses it).
2. Delete the stale `NOTE (Bug #5)` comment block above the `check_domain = ...`
   line in `check_all_records()`. The fix it describes is already applied further
   down; the stale note contradicts the code.
3. Fix the cache empty-result bug. In `checker.py`, every cache read is
   `if cached_result:` which misses when the stored value is an empty dict
   (this happens for PARENT_CAA when no parent CAA exists, so those domains get
   re-queried every time). Change `DNSCache.get()` in `cache.py` to return a
   sentinel: keep the API but in checker.py change every
   `if cached_result:` to `if cached_result is not None:`.
4. In `dns_inspector/ui/utils.py` `run_dns_checks()`: delete the
   `time.sleep(0.1)` line (and the now-unused `import time`).

**Acceptance criteria**
- `python -c "import dns_inspector.checker"` succeeds.
- `pytest tests/ -v -m "not integration"` passes.
- Calling `check_parent_caa_records('www.example.com')` twice on one checker
  produces a cache hit the second time (verify with `checker.cache.get_stats()`).

---

## Phase 1 — Structured CAA records + correct eligibility parsing

The root cause of most past bugs: CAA records are formatted into display strings
early, then regex-parsed back later. Replace with a structured type.

1. Create `dns_inspector/records.py`:

```python
from dataclasses import dataclass

KNOWN_CAA_TAGS = {"issue", "issuewild", "iodef"}

@dataclass(frozen=True)
class CAARecord:
    flags: int
    tag: str    # normalized lowercase
    value: str  # decoded UTF-8, errors="replace"

    @property
    def is_critical_unknown(self) -> bool:
        return bool(self.flags & 0x80) and self.tag not in KNOWN_CAA_TAGS

    def issuer_domain(self) -> str | None:
        """Return the issuer-domain-name from an issue/issuewild value,
        or None for non-issue tags. Per RFC 8659 section 4.2 the value is
        'issuer-domain-name [; parameters]'. An empty issuer-domain-name
        (value ';' or '') means no CA may issue."""
        if self.tag not in ("issue", "issuewild"):
            return None
        name = self.value.split(";", 1)[0].strip().lower()
        return name  # may be "" for deny-all

    def to_display(self) -> str:
        return f'{self.flags} {self.tag} "{self.value}"'
```

2. In `checker.py` `resolve_record()`, CAA branch: build `CAARecord` objects
   from `rdata.flags`, `str(rdata.tag)` lowercased, and
   `rdata.value.decode("utf-8", errors="replace")`. Store them in a NEW result
   key `result['caa_records']` (list of CAARecord). KEEP the existing
   `result['records']` list of display strings (use `rec.to_display()`) so the
   UI and formatter keep working unchanged.
3. Replace `DNSChecker._has_critical_unknown_caa()` internals to use the
   structured records: `any(r.is_critical_unknown for r in caa_records)`.
   In `check_all_records()`, take the records from
   `caa_raw.get('caa_records', [])` instead of parsing strings. Also store
   `results['caa_structured']` = that list (used by Phase 2 and Phase 4).
4. Rewrite `_is_eligible()` in `compliance.py` to use structured records via a
   new pure function in `compliance.py`:

```python
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
```

   IMPORTANT: exact match only. `'ssl.com' in value` is the bug being fixed —
   `notssl.com` must NOT be eligible.
5. `_is_eligible()` orchestration order:
   a. If `dns_status` contains SERVFAIL/REFUSED/TIMEOUT -> False (fail CLOSED).
   b. If domain's own zone has CAA records -> `evaluate_caa_eligibility` on them.
   c. Else if parent CAA found -> evaluate the parent's structured records.
      This requires `check_parent_caa_records()` to also return structured
      records: change its stored value per parent domain from a joined string to
      `{'display': <joined string>, 'records': list[CAARecord]}`. Update
      `formatter.simplify_parent_caa()` minimally to read the `'display'` key
      when the value is a dict (fall back to old behavior for strings).
   d. Else (no CAA anywhere) -> True.
6. In `run_compliance_tests()`: change the exception handler from
   `eligible = True` to `eligible = False` and fix the comment — failing OPEN is
   not conservative for a CA. Conservative = deny when status is unknown.

**Acceptance criteria**
- New unit tests in `tests/test_records.py` (write them):
  - `CAARecord(0, 'issue', 'notssl.com')` -> not eligible for ssl.com.
  - `CAARecord(0, 'issue', 'ssl.com')` -> eligible.
  - `CAARecord(0, 'issue', 'SSL.COM; account=123')` -> eligible (params ignored,
    case-insensitive).
  - `CAARecord(0, 'issue', ';')` -> deny-all, not eligible.
  - `CAARecord(128, 'futuretag', 'x')` -> critical unknown -> not eligible.
  - `CAARecord(0, 'issuewild', 'other.com')` + `CAARecord(0, 'issue', 'ssl.com')`
    with `wildcard=True` -> NOT eligible (issuewild set takes precedence).
  - Empty record list -> eligible.
- All existing unit tests still pass.
- `python -m dns_inspector.compliance` (network required): all 22 tests PASS.

---

## Phase 2 — Findings and remediation engine ("what needs to be fixed")

1. Create `dns_inspector/findings.py`:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    severity: str      # 'BLOCKER' | 'WARN' | 'INFO'
    code: str          # stable machine code, e.g. 'CAA_BLOCKS_CA'
    message: str       # what was observed
    remediation: str   # concrete action for the domain owner
```

2. Create `build_findings(results: dict, ca_domain="ssl.com") -> list[Finding]`
   in `findings.py`, consuming the dict returned by `check_all_records()`.
   Implement AT LEAST these findings (code -> condition -> remediation text):

   | code | severity | condition | remediation |
   |---|---|---|---|
   | `DOMAIN_NXDOMAIN` | BLOCKER | dns_status NXDOMAIN | Verify the domain is registered and spelled correctly; NXDOMAIN means it does not resolve. |
   | `DNS_LOOKUP_FAILED` | BLOCKER | dns_status SERVFAIL/REFUSED/TIMEOUT | Fix authoritative nameserver availability; issuance is denied while lookups fail. |
   | `CAA_DENY_ALL` | BLOCKER | relevant issue/issuewild issuer_domain == '' | Remove the `issue ";"` record or replace it with `0 issue "ssl.com"`. |
   | `CAA_BLOCKS_CA` | BLOCKER | CAA records exist, none permit ca_domain | Add `0 issue "ssl.com"` to the zone (list existing permitted CAs in message). |
   | `CAA_CRITICAL_UNKNOWN` | BLOCKER | any is_critical_unknown | Remove or correct the CAA record with unknown critical tag (flags >= 128). |
   | `CAA_BLOCKED_BY_PARENT` | BLOCKER | no CAA at domain, parent CAA exists and does not permit ca_domain | Add `0 issue "ssl.com"` at the domain, or update the parent zone `<parent>` CAA. |
   | `DNSSEC_CHAIN_BROKEN` | BLOCKER | dnssec issues mention SERVFAIL/validation failed | Re-sign the zone; check for expired RRSIGs and correct DS at the parent. |
   | `DS_MISSING` | WARN | DNSKEY present, DS missing at parent | Publish the DS record at your registrar to complete the chain of trust. |
   | `DNSSEC_NOT_ENABLED` | INFO | no DNSKEY | Consider enabling DNSSEC signing for the zone. |
   | `NO_CAA_RECORDS` | INFO | no CAA anywhere in tree | Any CA may issue. Consider adding `0 issue "ssl.com"` to restrict issuance. |
   | `NO_IP_RECORDS` | WARN | no A and no AAAA at final domain | Add an A or AAAA record if the host must be reachable for validation. |

3. In `check_all_records()`, append at the end:
   `results['findings'] = build_findings(results)` and
   `results['eligible'] = not any(f.severity == 'BLOCKER' for f in results['findings'])`.
   Keep all existing keys untouched.
4. In `ui/utils.py` `run_dns_checks()`: after building the DataFrame, add columns
   `eligible` ("Yes"/"No") and `fix_actions` (join of
   `f"[{f.severity}] {f.remediation}"` for non-INFO findings, '; ' separated,
   empty string if none). Drop the raw `findings` column from the DataFrame
   (objects don't render well); keep it available in the raw results list.

**Acceptance criteria**
- New `tests/test_findings.py` (write it, no network — construct results dicts
  by hand): at least one test per finding code above asserting it fires, plus a
  clean-domain test asserting `eligible=True` and no BLOCKERs.
- A domain result with `0 issue "letsencrypt.org"` produces `CAA_BLOCKS_CA` with
  remediation text containing `0 issue "ssl.com"`.
- All prior tests pass.

---

## Phase 2b — Make the display and exports agree with the findings

The UI layer currently computes its OWN eligibility signals with regex/substring
logic. Left alone, the styled table can contradict the `eligible` column
(e.g. `notssl.com` gets a green CAA cell). Files: `dns_inspector/ui/styler.py`,
`dns_inspector/ui/components.py`, `dns_inspector/formatter.py`.

1. **Color from findings, not regex flags.** In `DataFrameStyler`:
   - In `prepare_for_display()`, capture `self.eligible = self.df['eligible']`
     (the "Yes"/"No" column added in Phase 2) before any transformation.
   - Rewrite `style_caa_column` to color green when the row's `eligible` is
     "Yes" and red when "No"; keep the malicious flag override (red) and the
     grey 'See status' case. Delete the unconditional green for
     'No CAA records found' (a parent zone may still block issuance).
   - Add a styling rule for the `eligible` column itself: green for "Yes",
     red for "No".
2. **Fix the filter.** In `components.py` `create_filter_widgets`, replace the
   'Contains ssl.com' option in the CAA dropdown with an 'Eligible' dropdown
   (All / Yes / No) that filters on `filtered_df['eligible']`. Remove the
   `str.contains('ssl.com')` substring filter entirely.
3. **Column groups.** In `prepare_for_display()` add a group
   `'Issuance': ['eligible', 'fix_actions']` to `self.column_groups` (pick a
   distinct header color in `get_group_styles`, e.g. '#E74C3C') so both columns
   render styled and grouped in the table and the HTML export.
4. **Stop mutating display text.** In `formatter.py` `format_caa_records()`,
   remove the `deep_decode()` call — DNS values are not URL/HTML encoded, and
   decoding can corrupt legitimate values shown in the table and exports.
   Parse the raw string as-is. Keep `sanitize_value`/`html.escape` at render
   time. (The `ssl_com` flag this function returns is now unused for coloring;
   keep returning it for API compatibility but do not use it in the styler.)
5. **Summary stats.** In `apply_styling()`, add an "Issuance Eligibility" stat
   to the caption block: `X/N domains eligible for ssl.com issuance`.

**Acceptance criteria**
- Consistency invariant, verified by a unit test in `tests/test_styler.py`
  (construct a small results DataFrame by hand, no network): for every row,
  the CAA cell style is green iff `eligible == 'Yes'`.
- A hand-built row with caa `0 issue "notssl.com"` and `eligible == 'No'`
  renders a RED caa cell and RED eligible cell.
- A hand-built row with caa 'No CAA records found' but `eligible == 'No'`
  (parent-blocked) renders RED, not green.
- CSV export (raw df) and HTML export (styled df) both contain `eligible` and
  `fix_actions` columns with identical values.
- The Eligible filter with value 'No' returns only rows where eligible == 'No'.

---

## Phase 3 — Speed: concurrency and query reduction

Target: 100 domains in under 30 seconds on the quick profile.

1. **Thread-safe cache.** In `cache.py`, add `self._lock = threading.Lock()` in
   `__init__` and wrap the bodies of `get`, `store`, `get_stats`, `clear` in
   `with self._lock:`.
2. **Scan profiles.** In `config.py` add:

```python
PROFILES = {
    'quick': {'timeout': 2.0, 'lifetime': 4.0, 'deep_dnssec': False,
              'per_hop_cname_dnssec': False, 'parent_dnssec_ladder': False},
    'deep':  {'timeout': 3.0, 'lifetime': 5.0, 'deep_dnssec': True,
              'per_hop_cname_dnssec': True, 'parent_dnssec_ladder': True},
}
```

   Give `DNSChecker.__init__` a `profile='quick'` parameter storing the resolved
   dict on `self.profile`. Use `self.profile['timeout']/['lifetime']` in
   `get_resolver()`.
3. **Slim the DNSSEC probe.** In `check_dnssec()`, replace the
   3-record-type x 2-resolver loop:
   - Quick mode (`deep_dnssec=False`): ONE query — SOA with `want_dnssec=True`
     to `1.1.1.1`; on timeout only, retry once against `9.9.9.9`. AD flag ->
     validated; SERVFAIL -> chain broken; otherwise not validated.
   - Deep mode: keep the existing multi-type loop.
4. **Gate the expensive extras** in `check_all_records()`:
   - Per-hop CNAME DNSSEC checks only when `profile['per_hop_cname_dnssec']`.
   - `check_parent_dnssec()` ladder only when `profile['parent_dnssec_ladder']`;
     in quick mode set `results['parent_dnssec_checks'] = {}`.
5. **Parallelize within a domain.** In `check_all_records()`, run the four
   `resolve_record(check_domain, rt)` calls for A/AAAA/CNAME/CAA concurrently
   via `ThreadPoolExecutor(max_workers=4)` and collect results. Reuse the CAA
   result for the critical-flag check instead of calling `resolve_record` a
   second time (delete the duplicate `caa_raw = self.resolve_record(...)` call;
   use the already-fetched result).
6. **Parallelize across domains.** In `ui/utils.py` `run_dns_checks()`: use ONE
   shared `DNSChecker` and `ThreadPoolExecutor(max_workers=DNSConfig.DEFAULT_MAX_WORKERS)`
   with `executor.submit(checker.check_all_records, d)` per domain; update tqdm
   with `as_completed`. Preserve the input domain order in the final DataFrame
   (map future -> domain, sort results back to input order). Bump
   `DEFAULT_MAX_WORKERS` to 20.
7. **All-validating nameservers.** In `config.py` set
   `DEFAULT_NAMESERVERS = ['1.1.1.1', '8.8.8.8', '9.9.9.9']` (remove AdGuard and
   DNSWATCH — mixing non-validating resolvers makes DNSSEC results
   nondeterministic).
8. **Stop the parent-CAA climb early.** In `check_parent_caa_records()`, do not
   query single-label parents (skip when `parent_domain` has no dot, i.e. the
   TLD): `if '.' not in parent_domain: break`.

**Acceptance criteria**
- Write `scripts/benchmark.py`: reads N domains (use the 22 caatestsuite FQDNs +
  ssl.com, example.com, github.com repeated to 100 entries), times a full quick
  scan via `run_dns_checks`-equivalent logic (without ipywidgets — call the
  checker + executor directly), prints total seconds and cache stats.
- Benchmark completes 100 entries in < 30s (network required).
- `python -m dns_inspector.compliance` still passes 22/22 (use the DEEP profile
  for compliance runs — add `profile='deep'` to the checker in
  `run_compliance_tests`).
- Unit tests pass. Add a test that two threads storing/reading the cache
  concurrently (500 ops each) never raises and counters sum correctly.

---

## Phase 4 — CLI entry point

1. Create `dns_inspector/cli.py` using argparse (no new deps):

```
python -m dns_inspector scan DOMAIN [DOMAIN ...]
python -m dns_inspector scan --file domains.txt --output results.csv --format csv
python -m dns_inspector scan example.com --profile deep --format json
python -m dns_inspector compliance
```

   - `scan`: accepts positional domains and/or `--file` (one domain per line,
     `#` comments and blank lines ignored). Runs the concurrent scanner
     (do NOT import ipywidgets/tqdm.notebook in this path — use plain
     `tqdm.tqdm` or no progress bar with `--quiet`). Output formats: `table`
     (default, printed summary: domain, eligible, top blocker remediation),
     `csv`, `json` (findings serialized as list of dicts).
   - `compliance`: calls `run_compliance_tests()` with deep profile, exits
     nonzero if any test failed (usable in CI).
2. Create `dns_inspector/__main__.py` that calls `cli.main()`.
3. IMPORTANT: `ui/utils.py` imports `tqdm.notebook` and `IPython` at module
   top-level. The CLI must not import `dns_inspector.ui` at all. If shared batch
   logic is needed, move the core batch-runner (executor loop, no widgets) into
   a new `dns_inspector/batch.py` and have BOTH `ui/utils.py` and `cli.py` call
   it.

**Acceptance criteria**
- `python -m dns_inspector scan ssl.com` prints a table row with
  `eligible: Yes` (network required).
- `python -m dns_inspector scan deny.basic.caatestsuite.com` shows
  `eligible: No` with a `CAA_BLOCKS_CA` or `CAA_BLOCKED_BY_PARENT` remediation.
- `python -m dns_inspector scan --file x.txt --output r.csv --format csv`
  writes a CSV containing `domain,eligible,fix_actions` columns.
- CLI works in an environment WITHOUT jupyter/ipywidgets installed
  (verify: the cli module import graph never touches `dns_inspector.ui`).
- `python -m dns_inspector compliance` exits 0.

---

## Phase 5 — Test hardening

1. **Mock the unit tests.** `tests/test_checker.py` currently hits live DNS.
   Refactor using `unittest.mock.patch` on `dns.resolver.Resolver.resolve`
   (or inject a fake resolver object — `DNSChecker.get_resolver` is the seam):
   return canned answer objects for NOERROR/NXDOMAIN/NoAnswer/Timeout paths.
   Keep one live smoke test but mark it `@pytest.mark.integration`.
2. **Positive controls in compliance.** The current suite is deny-only, so a
   checker that always returns False scores 22/22. Add to `CAA_TEST_SUITE`:
   - `("ssl.com", True, "ssl.com's own CAA permits ssl.com")`
   - `("example.com", True, "no CAA records anywhere -> any CA may issue")`
   Keep expected values accurate: verify with `dig CAA ssl.com` before
   committing; if ssl.com's actual CAA does not include ssl.com, pick a domain
   that does or skip with a comment.
3. Strengthen `test_sanitize_removes_script_tags` to assert the exact escaped
   output (`&lt;script&gt;alert(1)&lt;/script&gt;`) instead of the current
   near-vacuous or-condition.

**Acceptance criteria**
- `pytest tests/ -m "not integration"` passes with networking disabled
  (verify by running with an unroutable resolver or in an offline env; at
  minimum, confirm no test calls the real `resolve` by asserting the mock was
  used).
- `pytest tests/test_compliance.py -m integration` passes 24/24.

---

## Phase 6 — Repo polish

1. `README.md` at root: what it does (2 paragraphs), quickstart (pip install +
   CLI examples), sample output table, compliance suite results, architecture
   summary (reuse CLAUDE.md's layout table), link to RFC 8659.
2. `pyproject.toml`: setuptools build, package `dns_inspector`, runtime deps
   `dnspython`, `pandas`, `tqdm`; extras `[ui]` = ipywidgets, jupyter;
   `[dev]` = pytest. Console script `caa-inspect = dns_inspector.cli:main`.
   Verify `pip install -e .` then `caa-inspect scan example.com` works.
3. `LICENSE`: MIT.
4. `.github/workflows/ci.yml`: on push/PR — Python 3.11 and 3.12 matrix,
   `pip install -e .[dev]`, run `pytest -m "not integration"`. Second job
   `workflow_dispatch` + weekly cron running the integration compliance suite.
5. Delete the duplicate `CAA_DNSSEC_Inspector.ipynb` at repo root (keep
   `notebooks/`). Rename `Caa dnssec inspector manifest.md` to
   `docs/MANIFEST.md` with `git mv`.
6. Update CLAUDE.md: new modules (records.py, findings.py, batch.py, cli.py),
   profiles, CLI usage, and mark this plan's phases complete.

**Acceptance criteria**
- Fresh venv: `pip install -e .` succeeds; `caa-inspect scan example.com` runs.
- CI workflow YAML is valid (`python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` after `pip install pyyaml`, or push and check).
- Only one notebook remains, under `notebooks/`.

---

## Commit strategy

One commit (or small commit group) per phase, message format:
`Phase N: <summary>` with a body listing the acceptance criteria that were
verified. Do not squash phases together.

## Definition of done

- 100-domain quick scan < 30s.
- Every denied domain in output carries at least one BLOCKER finding with a
  concrete remediation string.
- `notssl.com`-style substring false positives impossible (exact issuer match,
  covered by tests).
- 24/24 compliance tests pass (22 deny + 2 allow).
- Table coloring, filters, CSV export, and HTML export all derive from the same
  structured findings — no row where the CAA cell color disagrees with the
  `eligible` column.
- Unit tests pass offline; CI green; `pip install -e .` + `caa-inspect` work.
