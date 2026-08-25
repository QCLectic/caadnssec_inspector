from ..formatter import RecordFormatter


class DataFrameStyler:
    """Handle styling and formatting of DNS check results DataFrame."""

    def __init__(self, df, formatter=None):
        self.df = df.copy()
        self.formatter = formatter or RecordFormatter()
        self.caa_flags = {}
        self.dns_status = {}

    def prepare_for_display(self):
        """Prepare DataFrame for display by simplifying complex columns."""
        self.column_groups = {
            'Domain Information': ['domain', 'dns_status'],
            'DNSSEC Information': ['dnssec_status', 'parent_dnssec_checks'],
            'CAA Information': ['caa', 'parent_caa'],
            'CNAME Information': ['cname_traversal', 'cname_dnssec_checks'],
            'DNS Records': ['ip_records']
        }

        if 'a' in self.df.columns and 'aaaa' in self.df.columns:
            self.df['ip_records'] = self.df.apply(
                lambda row: self.formatter.format_ip_records(row['a'], row['aaaa']),
                axis=1
            )

        if 'dnssec_enabled' in self.df.columns and 'dnssec_issues' in self.df.columns:
            self.df['dnssec_status'] = self.df.apply(
                lambda row: self.formatter.format_dnssec_status(row['dnssec_enabled'], row['dnssec_issues']),
                axis=1
            )
            self.dns_status['dnssec_enabled'] = self.df['dnssec_enabled']
            self.dns_status['dnssec_issues'] = self.df['dnssec_issues']

        if 'dns_status' in self.df.columns:
            self.dns_status['original'] = self.df['dns_status']
            self.df['dns_status'] = self.df['dns_status'].apply(self.formatter.format_dns_status)

        if 'caa' in self.df.columns:
            results = self.df['caa'].apply(self.formatter.format_caa_records)
            self.df['caa'] = results.apply(lambda x: x[0])
            self.caa_flags = {
                'malicious': results.apply(lambda x: x[1]),
                'ssl_com': results.apply(lambda x: x[2])
            }

        simplify_mappings = {
            'cname_traversal': self.formatter.simplify_cname_traversal,
            'cname_dnssec_checks': self.formatter.simplify_cname_dnssec_checks,
            'parent_dnssec_checks': self.formatter.simplify_parent_dnssec_checks
        }

        for col, func in simplify_mappings.items():
            if col in self.df.columns:
                self.df[col] = self.df[col].apply(func)

        if 'parent_caa' in self.df.columns:
            self.df['parent_caa'] = self.df['parent_caa'].apply(self.formatter.simplify_parent_caa)

        columns_to_drop = []
        if 'dnssec_enabled' in self.df.columns and 'dnssec_status' in self.df.columns:
            columns_to_drop.extend(['dnssec_enabled', 'dnssec_issues'])

        if 'ip_records' in self.df.columns:
            columns_to_drop.extend(['a', 'aaaa'])

        if 'cname' in self.df.columns and 'cname_traversal' in self.df.columns:
            columns_to_drop.append('cname')

        self.df = self.df.drop(columns=columns_to_drop, errors='ignore')
        return self.df

    def style_dns_status(self, val):
        if not isinstance(val, str):
            return ''
        if 'NOERROR' in val:
            return 'background-color: #2ECC71; color: white; font-weight: bold;'
        elif 'NXDOMAIN' in val or 'SERVFAIL' in val or 'REFUSED' in val or 'ERROR' in val:
            return 'background-color: #FF6B6B; color: white; font-weight: bold;'
        elif 'TIMEOUT' in val:
            return 'background-color: #F39C12; color: white; font-weight: bold;'
        return ''

    def style_dnssec_status(self, val):
        if not isinstance(val, str):
            return ''
        if 'Status: Enabled' in val:
            return 'background-color: #3498DB; color: white; font-weight: bold;'
        elif 'Issues: None' not in val and 'Status: Not Enabled' in val:
            return 'background-color: #F39C12; color: white; font-weight: bold;'
        elif 'misconfigured' in val.lower() or ('Issues:' in val and 'None' not in val):
            return 'background-color: #FF6B6B; color: white; font-weight: bold;'
        return ''

    def style_caa_column(self, v, i):
        if not isinstance(v, str):
            return ''
        if 'See status' in v:
            return 'background-color: #ECECEC; color: #666666;'
        if 'malicious' in self.caa_flags and i < len(self.caa_flags['malicious']):
            if self.caa_flags['malicious'].iloc[i]:
                return 'background-color: #FF6B6B; color: white; font-weight: bold;'
            elif self.caa_flags['ssl_com'].iloc[i]:
                return 'background-color: #2ECC71; color: white; font-weight: bold;'
            elif 'No CAA records found' in str(v):
                return 'background-color: #2ECC71; color: white; font-weight: bold;'
            else:
                return 'background-color: #FF6B6B; color: white; font-weight: bold;'
        return ''

    def style_see_status(self, val):
        if isinstance(val, str) and 'See status' in val:
            return 'background-color: #ECECEC; color: #666666;'
        return ''

    def get_group_styles(self):
        group_styles = []
        group_colors = {
            'Domain Information': '#4CAF50',
            'DNSSEC Information': '#3498DB',
            'CAA Information': '#9B59B6',
            'CNAME Information': '#F39C12',
            'DNS Records': '#1ABC9C'
        }

        for group, color in group_colors.items():
            if hasattr(self, 'column_groups'):
                cols = self.column_groups.get(group, [])
                for col in cols:
                    if col in self.df.columns:
                        col_idx = self.df.columns.get_loc(col)
                        group_styles.append({
                            'selector': f'th.col{col_idx}',
                            'props': [
                                ('background-color', color),
                                ('color', 'white'),
                                ('font-weight', 'bold'),
                                ('border-bottom', f'3px solid {color}')
                            ]
                        })
        return group_styles

    def apply_styling(self):
        """Apply all styling rules to the DataFrame."""
        styled_df = self.df.style

        if 'dns_status' in self.df.columns:
            styled_df = styled_df.apply(
                lambda s: [self.style_dns_status(x) for x in s] if s.name == 'dns_status' else [''] * len(s),
                axis=0
            )

        if 'dnssec_status' in self.df.columns:
            styled_df = styled_df.apply(
                lambda s: [self.style_dnssec_status(x) for x in s] if s.name == 'dnssec_status' else [''] * len(s),
                axis=0
            )

        if 'caa' in self.df.columns and self.caa_flags:
            styled_df = styled_df.apply(
                lambda x: [self.style_caa_column(v, i) for i, v in enumerate(x)] if x.name == 'caa' else [''] * len(x),
                axis=0
            )

        styled_df = styled_df.map(self.style_see_status)

        styled_df = styled_df.set_properties(**{
            'white-space': 'pre-wrap',
            'text-align': 'left',
            'max-width': '250px',
            'overflow': 'hidden',
            'text-overflow': 'ellipsis'
        })

        group_styles = self.get_group_styles()
        base_header_style = [{
            'selector': 'th',
            'props': [('background-color', '#4CAF50'), ('color', 'white'), ('font-weight', 'bold')]
        }]
        styled_df = styled_df.set_table_styles(base_header_style + group_styles)

        styled_df = styled_df.set_table_styles([{
            'selector': 'td',
            'props': [('cursor', 'pointer'), ('transition', 'max-width 0.3s')]
        }], overwrite=False)

        if hasattr(self, 'dns_status') and 'dnssec_enabled' in self.dns_status:
            total_domains = len(self.df)
            dnssec_enabled = sum(self.dns_status['dnssec_enabled'] == 'Yes')
            caa_records = sum(~self.df['caa'].str.contains('No CAA records found', na=False)) if 'caa' in self.df.columns else 0
            error_domains = 0
            if 'original' in self.dns_status:
                error_domains = sum(~self.dns_status['original'].str.contains('NOERROR', na=False))
            cname_usage = sum(self.df['cname_traversal'] != 'No CNAME') if 'cname_traversal' in self.df.columns else 0

            stats_html = f"""
            <div style="margin: 10px 0; padding: 15px; background-color: #212529; border-radius: 5px; border: 1px solid #343a40; color: #e9ecef;">
                <h3 style="margin-top: 0; color: #8bc34a;">DNS Summary Statistics</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 20px;">
                    <div><h4>DNSSEC Adoption</h4><p>{dnssec_enabled}/{total_domains} domains have DNSSEC enabled ({dnssec_enabled/total_domains*100:.1f}%)</p></div>
                    <div><h4>CAA Implementation</h4><p>{caa_records}/{total_domains} domains have CAA records ({caa_records/total_domains*100:.1f}%)</p></div>
                    <div><h4>Error States</h4><p>{error_domains}/{total_domains} domains have DNS errors ({error_domains/total_domains*100:.1f}%)</p></div>
                    <div><h4>CNAME Usage</h4><p>{cname_usage}/{total_domains} domains use CNAME records ({cname_usage/total_domains*100:.1f}%)</p></div>
                </div>
            </div>
            """
            styled_df = styled_df.set_caption(stats_html)

        styled_df = styled_df.format(escape="html")
        return styled_df

    def get_styled_df(self):
        """Prepare and style DataFrame for display."""
        self.prepare_for_display()
        return self.apply_styling()
