from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .cache import DNSCache
from .config import DNSConfig
from .records import CAARecord


class DNSChecker:
    """Centralized class for DNS record checking functionality."""

    def __init__(self, config=None, cache=None):
        self.config = config or DNSConfig()
        self.cache = cache or DNSCache()

    def get_resolver(self):
        """Create a properly configured resolver instance."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.DEFAULT_TIMEOUT
        resolver.lifetime = self.config.DEFAULT_LIFETIME
        resolver.nameservers = self.config.DEFAULT_NAMESERVERS
        return resolver

    def resolve_record(self, domain, record_type):
        """Resolve a DNS record with caching and error handling."""
        cached_result = self.cache.get(domain, record_type)
        if cached_result is not None:
            return cached_result

        resolver = self.get_resolver()
        result = {
            'domain': domain,
            'record_type': record_type,
            'records': [],
            'status': 'unknown',
            'error': None
        }

        try:
            answers = resolver.resolve(domain, record_type)

            if record_type == 'CAA':
                caa_records = [
                    CAARecord(
                        flags=rdata.flags,
                        tag=(rdata.tag.decode('ascii', errors='replace')
                             if isinstance(rdata.tag, bytes) else str(rdata.tag)).lower(),
                        value=rdata.value.decode('utf-8', errors='replace'),
                    )
                    for rdata in answers
                ]
                result['caa_records'] = caa_records
                result['records'] = [rec.to_display() for rec in caa_records]
            elif record_type == 'CNAME':
                result['records'] = [str(rdata.target).rstrip('.') for rdata in answers]
            else:
                result['records'] = [str(rdata) for rdata in answers]

            result['status'] = 'NOERROR'

        except dns.resolver.NoAnswer:
            result['status'] = 'NOERROR'
            result['error'] = f'No {record_type} records found'
        except dns.resolver.NXDOMAIN:
            result['status'] = 'NXDOMAIN'
            result['error'] = 'Domain does not exist'
        except dns.resolver.NoNameservers:
            result['status'] = 'SERVFAIL/REFUSED'
            result['error'] = 'DNS query refused or server failure'
        except dns.exception.Timeout:
            result['status'] = 'TIMEOUT'
            result['error'] = 'DNS query timed out'
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = str(e)

        self.cache.store(domain, record_type, result)
        return result

    def check_dnssec(self, domain):
        """Check if DNSSEC is enabled and properly configured."""
        cached_result = self.cache.get(domain, 'DNSSEC')
        if cached_result is not None:
            return cached_result

        result = {
            'enabled': False,
            'issues': None
        }

        dnskey_result = self.resolve_record(domain, 'DNSKEY')

        if dnskey_result['status'] == 'NOERROR' and dnskey_result['records']:
            result['enabled'] = True
        else:
            result['enabled'] = False
            result['issues'] = dnskey_result.get('error', 'No DNSKEY records found')
            self.cache.store(domain, 'DNSSEC', result)
            return result

        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            ds_result = self.resolve_record(domain, 'DS')
            if ds_result['status'] != 'NOERROR' or not ds_result['records']:
                result['issues'] = 'DNSSEC issue: No DS records found at parent zone'

        # Validate the DNSSEC chain by sending a query with the DO (DNSSEC OK) bit set
        # to a validating resolver and inspecting the response:
        #   AD flag set  → chain validated end-to-end
        #   SERVFAIL     → chain broken (expired sigs, missing records, etc.)
        try:
            qname = dns.name.from_text(domain)
            validated = False
            chain_broken = False

            for rdtype in [dns.rdatatype.A, dns.rdatatype.SOA, dns.rdatatype.MX]:
                if validated or chain_broken:
                    break
                request = dns.message.make_query(qname, rdtype, want_dnssec=True)
                for ns in ['1.1.1.1', '9.9.9.9']:
                    try:
                        response = dns.query.udp(
                            request, ns, timeout=self.config.DEFAULT_TIMEOUT
                        )
                        if response.rcode() == dns.rcode.SERVFAIL:
                            chain_broken = True
                            break
                        if response.flags & dns.flags.AD:
                            validated = True
                            break
                    except dns.exception.Timeout:
                        continue
                    except Exception:
                        continue

            if chain_broken and not result['issues']:
                result['issues'] = 'DNSSEC validation failed: SERVFAIL from validating resolver'
            elif not validated and not result['issues']:
                result['issues'] = 'DNSSEC chain not validated (no AD flag in resolver response)'

        except Exception as e:
            if not result['issues']:
                result['issues'] = f'DNSSEC validation check error: {str(e)}'

        self.cache.store(domain, 'DNSSEC', result)
        return result

    def traverse_cname_chain(self, domain, max_depth=None):
        """Follow CNAME records to find the ultimate target domain."""
        if max_depth is None:
            max_depth = self.config.DEFAULT_MAX_DEPTH

        cached_result = self.cache.get(domain, 'CNAME_CHAIN')
        if cached_result is not None:
            return cached_result

        result = {
            'original_domain': domain,
            'final_domain': domain,
            'cname_chain': []
        }

        current_domain = domain

        for depth in range(max_depth):
            cname_result = self.resolve_record(current_domain, 'CNAME')

            if cname_result['status'] == 'NOERROR' and cname_result['records']:
                cname_target = cname_result['records'][0]

                result['cname_chain'].append({
                    'source': current_domain,
                    'target': cname_target
                })

                current_domain = cname_target
                result['final_domain'] = cname_target
            else:
                if cname_result['error'] and 'No CNAME records found' not in cname_result['error']:
                    result['cname_chain'].append({
                        'source': current_domain,
                        'error': cname_result['error']
                    })
                break

        self.cache.store(domain, 'CNAME_CHAIN', result)
        return result

    def check_parent_caa_records(self, domain):
        """Check CAA records for parent domains of a given domain."""
        cached_result = self.cache.get(domain, 'PARENT_CAA')
        if cached_result is not None:
            return cached_result

        parent_caa_results = {}
        domain_parts = domain.split('.')

        for i in range(1, len(domain_parts)):
            parent_domain = '.'.join(domain_parts[i:])
            caa_result = self.resolve_record(parent_domain, 'CAA')

            if caa_result['status'] == 'NOERROR' and caa_result['records']:
                parent_caa_results[parent_domain] = {
                    'display': '\n'.join(caa_result['records']),
                    'records': caa_result.get('caa_records', []),
                }
                break

        self.cache.store(domain, 'PARENT_CAA', parent_caa_results)
        return parent_caa_results

    def check_parent_dnssec(self, domain):
        """Check DNSSEC status for parent domains."""
        cached_result = self.cache.get(domain, 'PARENT_DNSSEC')
        if cached_result is not None:
            return cached_result

        parent_dnssec_results = {}
        domain_parts = domain.split('.')

        for i in range(1, len(domain_parts)):
            parent_domain = '.'.join(domain_parts[i:])
            dnssec_result = self.check_dnssec(parent_domain)

            parent_dnssec_results[parent_domain] = {
                'enabled': "Yes" if dnssec_result['enabled'] else "No",
                'issues': dnssec_result['issues'] if dnssec_result['issues'] else "None detected"
            }

            if dnssec_result['enabled']:
                break

        self.cache.store(domain, 'PARENT_DNSSEC', parent_dnssec_results)
        return parent_dnssec_results

    @staticmethod
    def _has_critical_unknown_caa(caa_records):
        """Return True if any CAA record has an unknown critical property (flags >= 128).

        Per RFC 8659: if a CAA record has flag bit 7 set (value >= 128) and the tag is
        not a known property tag (issue, issuewild, iodef), a CA must refuse to issue.
        """
        return any(record.is_critical_unknown for record in caa_records)

    def check_all_records(self, domain):
        """Comprehensive check of all relevant DNS records for a domain."""
        results = {'domain': domain}

        dnssec_result = self.check_dnssec(domain)
        results['dnssec_enabled'] = "Yes" if dnssec_result['enabled'] else "No"
        results['dnssec_issues'] = dnssec_result['issues'] if dnssec_result['issues'] else "None detected"

        cname_traversal = self.traverse_cname_chain(domain)
        results['cname_traversal'] = cname_traversal

        check_domain = cname_traversal.get('final_domain', domain)

        results['cname_dnssec_checks'] = {}
        if cname_traversal.get('cname_chain'):
            for cname_hop in cname_traversal['cname_chain']:
                domains_to_check = []

                source = cname_hop.get('source')
                if isinstance(source, str):
                    domains_to_check.append(source)

                target = cname_hop.get('target')
                if isinstance(target, str):
                    domains_to_check.append(target)

                for hop_domain in domains_to_check:
                    hop_dnssec = self.check_dnssec(hop_domain)
                    results['cname_dnssec_checks'][hop_domain] = {
                        'enabled': "Yes" if hop_dnssec['enabled'] else "No",
                        'issues': hop_dnssec['issues'] if hop_dnssec['issues'] else "None detected"
                    }

        results['parent_dnssec_checks'] = self.check_parent_dnssec(domain)

        caa_raw = None
        for record_type in ['A', 'AAAA', 'CNAME', 'CAA']:
            record_result = self.resolve_record(check_domain, record_type)
            if record_type == 'CAA':
                caa_raw = record_result

            if record_result['records']:
                results[record_type.lower()] = '\n'.join(record_result['records'])
            else:
                results[record_type.lower()] = record_result['error'] or f'No {record_type} records found'

        caa_structured = caa_raw.get('caa_records', []) if caa_raw else []
        results['caa_structured'] = caa_structured
        if caa_structured and self._has_critical_unknown_caa(caa_structured):
            results['caa_critical_deny'] = True

        if 'No CAA records found' in results.get('caa', ''):
            # Tree climbing must start from the original domain (RFC 8659), not the
            # CNAME final target.
            parent_caa = self.check_parent_caa_records(domain)
            if parent_caa:
                results['parent_caa'] = parent_caa

        if any('Domain does not exist' in str(results.get(key, '')) for key in ['a', 'aaaa', 'cname', 'caa']):
            results['dns_status'] = 'NXDOMAIN - Domain does not exist'
        elif any('DNS query refused or server failure' in str(results.get(key, '')) for key in ['a', 'aaaa', 'cname', 'caa']):
            results['dns_status'] = 'SERVFAIL/REFUSED - Server failed to complete the DNS request or refused the query'
        else:
            results['dns_status'] = 'NOERROR - No DNS errors detected'

        return results
