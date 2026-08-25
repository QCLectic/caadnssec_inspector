import html
import re
import urllib.parse


class RecordFormatter:
    """Handle sanitization and formatting of DNS records."""

    @staticmethod
    def sanitize_value(value, max_length=500):
        """Sanitize a value against XSS by HTML-escaping, then truncating."""
        if not isinstance(value, str):
            return str(value)
        sanitized = html.escape(str(value))
        return sanitized[:max_length]

    @staticmethod
    def deep_decode(encoded_str, max_depth=5):
        """Recursively decode encoded strings (URL encoding, HTML entities)."""
        if not isinstance(encoded_str, str):
            return str(encoded_str)

        prev_str = encoded_str
        decoded_str = urllib.parse.unquote(encoded_str)
        depth = 0

        while decoded_str != prev_str and depth < max_depth:
            prev_str = decoded_str
            decoded_str = urllib.parse.unquote(decoded_str)
            depth += 1

        prev_str = decoded_str
        decoded_str = html.unescape(decoded_str)
        depth = 0

        while decoded_str != prev_str and depth < max_depth:
            prev_str = decoded_str
            decoded_str = html.unescape(decoded_str)
            depth += 1

        return decoded_str

    @staticmethod
    def format_caa_records(caa_value):
        """Format CAA records with security classification."""
        if not isinstance(caa_value, str):
            return "No CAA records", False, True

        if 'No CAA records found' in caa_value:
            return 'No CAA records found', False, True

        is_malicious = False
        contains_ssl_com = False

        try:
            decoded = RecordFormatter.deep_decode(caa_value)

            # Bug #6: issue ";" means explicit deny-all — no CA may issue.
            if re.search(r'\bissue\b\s+["\'];["\']', decoded, re.IGNORECASE):
                return 'CAA deny-all: issue ";" (no CA may issue)', False, False

            formatted_records = []
            for line in decoded.split('\n'):
                clean_line = line.strip()

                # Bug #3 fix: re.IGNORECASE on issue/issuewild tags (RFC 8659).
                std_match = re.search(
                    r'(\d+)\s+(issue|issuewild)\s+["\']([^"\']+)["\']',
                    clean_line, re.IGNORECASE
                )
                if std_match:
                    tag = std_match.group(2).lower()
                    domain = std_match.group(3)
                    formatted_records.append(f"{tag}: {domain}")
                    if 'ssl.com' in domain.lower():
                        contains_ssl_com = True
                    continue

                if re.search(r'\b(issue|issuewild)\b', clean_line, re.IGNORECASE) and re.search(r'\w+\.\w+', clean_line):
                    domain_match = re.search(r'["\']?([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})["\']?', clean_line)
                    if domain_match:
                        domain = domain_match.group(1)
                        tag = 'issuewild' if re.search(r'\bissuewild\b', clean_line, re.IGNORECASE) else 'issue'
                        formatted_records.append(f"{tag}: {domain}")
                        if 'ssl.com' in domain.lower():
                            contains_ssl_com = True
                    continue

                prop_match = re.search(r'(\d+)\s+(\w+)\s+["\']([^"\']+)["\']', clean_line)
                if prop_match:
                    tag = prop_match.group(2)
                    value = prop_match.group(3)
                    formatted_records.append(f"{tag}: {value}")

            if formatted_records:
                return ", ".join(formatted_records), is_malicious, contains_ssl_com
            else:
                cleaned = re.sub(r'\s+', ' ', decoded).strip()
                if len(cleaned) > 80:
                    cleaned = cleaned[:80] + "..."

                if 'ssl.com' in decoded.lower():
                    contains_ssl_com = True

                return f"CAA value: {cleaned}", is_malicious, contains_ssl_com

        except Exception as e:
            return f"Error parsing CAA: {str(e)[:50]}", True, False

    @staticmethod
    def simplify_cname_traversal(val):
        """Simplify CNAME traversal to final domain name."""
        if isinstance(val, dict):
            if val.get('cname_chain'):
                return val.get('final_domain', 'Unknown')
            if val.get('error'):
                return 'Error'
        return 'No CNAME'

    @staticmethod
    def simplify_cname_dnssec_checks(val):
        """Simplify CNAME DNSSEC checks to a summary."""
        if not isinstance(val, dict):
            return 'Unknown'

        enabled_domains = [
            domain for domain, details in val.items()
            if details.get('enabled') == 'Yes'
        ]
        issue_domains = [
            domain for domain, details in val.items()
            if (details.get('enabled') == 'Yes' and
                details.get('issues') and
                details.get('issues') != 'None detected')
        ]

        if enabled_domains and not issue_domains:
            return 'DNSSEC enabled'
        elif issue_domains:
            return 'DNSSEC misconfigured'
        else:
            return 'DNSSEC not enabled'

    @staticmethod
    def format_dnssec_status(enabled, issues):
        """Format DNSSEC status in a standardized way."""
        if not isinstance(enabled, str):
            enabled = str(enabled)

        status = "Enabled" if enabled == "Yes" else "Not Enabled"

        if not issues or issues == "None detected":
            issue_text = "None"
        else:
            if "No DNSKEY records found" in issues:
                issue_text = "No DNSKEY records"
            elif "Domain does not exist" in issues:
                issue_text = "Domain does not exist"
            elif "DNS query timed out" in issues:
                issue_text = "See status"
            elif "DNS query refused" in issues:
                issue_text = "See status"
            else:
                issue_text = issues[:50] + "..." if len(issues) > 50 else issues

        return f"Status: {status}, Issues: {issue_text}"

    @staticmethod
    def format_dns_status(status):
        """Format DNS status in a standardized way."""
        if not isinstance(status, str):
            return "Unknown"

        if "NOERROR" in status:
            code = "NOERROR"
            details = "No errors"
        elif "NXDOMAIN" in status:
            code = "NXDOMAIN"
            details = "Domain does not exist"
        elif "SERVFAIL" in status or "REFUSED" in status:
            code = "SERVFAIL/REFUSED"
            details = "Server error or query refused"
        elif "TIMEOUT" in status:
            code = "TIMEOUT"
            details = "Query timed out"
        else:
            code = "UNKNOWN"
            details = status

        return f"Status: {code}, Details: {details}"

    @staticmethod
    def format_ip_records(a_records, aaaa_records):
        """Combine A and AAAA records into a single field."""
        a_valid = isinstance(a_records, str) and "No A records found" not in a_records and "Domain does not exist" not in a_records
        aaaa_valid = isinstance(aaaa_records, str) and "No AAAA records found" not in aaaa_records and "Domain does not exist" not in aaaa_records

        if a_valid and aaaa_valid:
            return f"IPv4: {a_records}, IPv6: {aaaa_records}"
        elif a_valid:
            return f"IPv4: {a_records}"
        elif aaaa_valid:
            return f"IPv6: {aaaa_records}"
        elif "Domain does not exist" in str(a_records) or "Domain does not exist" in str(aaaa_records):
            return "See status"
        elif "DNS query" in str(a_records) or "DNS query" in str(aaaa_records):
            return "See status"
        else:
            return "No IP records"

    @staticmethod
    def simplify_parent_dnssec_checks(val):
        """Simplify parent DNSSEC checks to a summary of the most relevant domain."""
        if not isinstance(val, dict):
            return 'na'

        sorted_domains = sorted(
            val.keys(),
            key=lambda x: len(x.split('.')),
            reverse=True
        )

        for domain in sorted_domains:
            domain_parts = domain.split('.')
            if len(domain_parts) <= 2:
                continue

            base_domain = '.'.join(domain_parts[-2:])
            details = val.get(domain, {})
            if details.get('enabled') == 'Yes':
                return f"{base_domain}:enabled"
            elif details.get('enabled') == 'No':
                return f"{base_domain}:disabled"

        return 'na'

    @staticmethod
    def simplify_parent_caa(val):
        """Simplify parent CAA records to a summary."""
        if not isinstance(val, dict):
            return 'No parent CAA'

        for domain, records in val.items():
            if isinstance(records, dict):
                records = records.get('display', '')

            if isinstance(records, str):
                decoded = RecordFormatter.deep_decode(records)

                caa_info = []
                for match in re.finditer(
                    r'(\d+)\s+(issue|issuewild)\s+["\']([^"\']+)["\']', decoded, re.IGNORECASE
                ):
                    tag = match.group(2).lower()
                    value = match.group(3)
                    caa_info.append(f"{tag}: {value}")

                if caa_info:
                    return f"{domain}: {', '.join(caa_info)}"

                cleaned = re.sub(r'\s+', ' ', decoded).strip()
                if len(cleaned) > 80:
                    cleaned = cleaned[:80] + "..."
                return f"{domain}: {cleaned}"

            elif isinstance(records, list):
                decoded_records = [RecordFormatter.deep_decode(r) for r in records]
                return f"{domain}: {' | '.join(decoded_records)}"

        return 'No parent CAA'
