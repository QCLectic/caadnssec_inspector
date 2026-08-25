import ipywidgets as widgets
from IPython.display import display, HTML

from ..config import DNSConfig
from .styler import DataFrameStyler
from .utils import UIUtils


class UIComponents:
    """Enhanced UI components for DNS checker."""

    @staticmethod
    def create_download_options(df, styled_df):
        """Create download options with multiple formats."""
        download_header = widgets.HTML(
            """<div style="background-color: #4CAF50; color: white; padding: 10px;
                          margin: 10px 0; border-radius: 5px; font-weight: bold;">
                 Download Options
               </div>"""
        )

        csv_link = UIUtils.create_download_link(df, "Download CSV", "dns_results.csv")
        csv_widget = widgets.HTML(value=csv_link.data)

        html_link = UIUtils.export_html(styled_df, "Download HTML", "dns_results.html")
        html_widget = widgets.HTML(value=html_link.data)

        download_container = widgets.HBox([
            widgets.VBox([widgets.HTML(value='<b>Raw Data:</b>'), csv_widget]),
            widgets.VBox([widgets.HTML(value='<b>Formatted Table:</b>'), html_widget])
        ])

        return widgets.VBox([download_header, download_container])

    @staticmethod
    def create_filter_widgets(df):
        """Create filter widgets for the DataFrame."""
        filters_container = widgets.VBox()

        filter_header = widgets.HTML(
            """<div style="background-color: #4CAF50; color: white; padding: 10px;
                          margin-bottom: 10px; border-radius: 5px; font-weight: bold;">
                 Filter Results
               </div>"""
        )

        domain_filter = widgets.Text(
            description='Domain:',
            placeholder='Filter by domain name...',
            style={'description_width': '100px'}
        )

        dnssec_filter = widgets.Dropdown(
            options=['All', 'Enabled', 'Not Enabled', 'Misconfigured'],
            value='All',
            description='DNSSEC:',
            style={'description_width': '100px'}
        )

        status_filter = widgets.Dropdown(
            options=['All', 'NOERROR', 'NXDOMAIN', 'SERVFAIL/REFUSED', 'TIMEOUT'],
            value='All',
            description='DNS Status:',
            style={'description_width': '100px'}
        )

        caa_filter = widgets.Dropdown(
            options=['All', 'Has CAA', 'No CAA', 'SSL.com', 'Other CA'],
            value='All',
            description='CAA Records:',
            style={'description_width': '100px'}
        )

        apply_button = widgets.Button(description='Apply Filters', button_style='success', icon='filter')
        reset_button = widgets.Button(description='Reset Filters', button_style='warning', icon='refresh')
        results_count = widgets.HTML(value=f"<b>Showing all {len(df)} domains</b>")

        button_container = widgets.HBox([apply_button, reset_button, results_count])

        filters_container.children = [
            filter_header,
            domain_filter,
            widgets.HBox([dnssec_filter, status_filter, caa_filter]),
            button_container
        ]

        output = widgets.Output()

        def apply_filters(b):
            domain_val = domain_filter.value.lower()
            dnssec_val = dnssec_filter.value
            status_val = status_filter.value
            caa_val = caa_filter.value

            filtered_df = df.copy()

            if domain_val:
                filtered_df = filtered_df[filtered_df['domain'].str.lower().str.contains(domain_val)]

            if dnssec_val != 'All' and 'dnssec_status' in filtered_df.columns:
                if dnssec_val == 'Enabled':
                    filtered_df = filtered_df[filtered_df['dnssec_status'].str.contains('Status: Enabled')]
                elif dnssec_val == 'Not Enabled':
                    filtered_df = filtered_df[filtered_df['dnssec_status'].str.contains('Status: Not Enabled')]
                elif dnssec_val == 'Misconfigured':
                    filtered_df = filtered_df[
                        (filtered_df['dnssec_status'].str.contains('Status: Enabled')) &
                        (~filtered_df['dnssec_status'].str.contains('Issues: None'))
                    ]

            if status_val != 'All' and 'dns_status' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['dns_status'].str.contains(status_val)]

            if caa_val != 'All' and 'caa' in filtered_df.columns:
                if caa_val == 'Has CAA':
                    filtered_df = filtered_df[~filtered_df['caa'].str.contains('No CAA records found')]
                elif caa_val == 'No CAA':
                    filtered_df = filtered_df[filtered_df['caa'].str.contains('No CAA records found')]
                elif caa_val == 'SSL.com':
                    filtered_df = filtered_df[filtered_df['caa'].str.lower().str.contains('ssl.com')]
                elif caa_val == 'Other CA':
                    filtered_df = filtered_df[
                        (~filtered_df['caa'].str.contains('No CAA records found')) &
                        (~filtered_df['caa'].str.lower().str.contains('ssl.com'))
                    ]

            results_count.value = f"<b>Showing {len(filtered_df)} of {len(df)} domains</b>"
            styler = DataFrameStyler(filtered_df)
            styled = styler.get_styled_df()

            output.clear_output()
            with output:
                display(filters_container)
                display(styled)
                print("\nDownload options:")
                display(UIUtils.create_download_link(filtered_df, "Download CSV", "filtered_dns_results.csv"))
                display(UIUtils.export_html(styled, "Download HTML", "filtered_dns_results.html"))

        def reset_filters(b):
            domain_filter.value = ''
            dnssec_filter.value = 'All'
            status_filter.value = 'All'
            caa_filter.value = 'All'
            results_count.value = f"<b>Showing all {len(df)} domains</b>"
            styler = DataFrameStyler(df)
            styled = styler.get_styled_df()

            output.clear_output()
            with output:
                display(filters_container)
                display(styled)
                print("\nDownload options:")
                display(UIUtils.create_download_link(df, "Download CSV", "dns_results.csv"))
                display(UIUtils.export_html(styled, "Download HTML", "dns_results.html"))

        apply_button.on_click(apply_filters)
        reset_button.on_click(reset_filters)

        return {'filters': filters_container, 'output': output, 'apply': apply_filters, 'reset': reset_filters}

    @staticmethod
    def create_collapsible_sections(styled_df):
        """Create collapsible sections for column groups."""
        column_groups = {
            'Domain Information': ['domain', 'dns_status'],
            'DNSSEC Information': ['dnssec_status', 'parent_dnssec_checks'],
            'CAA Information': ['caa', 'parent_caa'],
            'CNAME Information': ['cname_traversal', 'cname_dnssec_checks'],
            'DNS Records': ['ip_records']
        }

        collapsible_html = """
        <style>
            .collapsible-section { margin-bottom: 10px; border-radius: 5px; overflow: hidden; }
            .collapsible-header { cursor: pointer; padding: 10px 15px; font-weight: bold; color: white; }
            .collapsible-content { display: block; padding: 10px; border: 1px solid #ddd; border-top: none; }
            .domain-section .collapsible-header { background-color: #4CAF50; }
            .dnssec-section .collapsible-header { background-color: #3498DB; }
            .caa-section .collapsible-header { background-color: #9B59B6; }
            .cname-section .collapsible-header { background-color: #F39C12; }
            .records-section .collapsible-header { background-color: #1ABC9C; }
        </style>
        <script>
            function toggleSection(sectionId) {
                var content = document.getElementById('content-' + sectionId);
                content.style.display = (content.style.display === 'none') ? 'block' : 'none';
            }
        </script>
        """

        html_content = collapsible_html
        for i, (group_name, columns) in enumerate(column_groups.items()):
            group_class = group_name.lower().replace(' ', '-') + '-section'
            html_content += f"""
            <div class="collapsible-section {group_class}">
                <div class="collapsible-header" onclick="toggleSection({i})">{group_name}</div>
                <div class="collapsible-content" id="content-{i}">
            """
            for col in columns:
                if col in styled_df.columns:
                    html_content += styled_df[[col]].to_html()
            html_content += "</div></div>"

        return HTML(html_content)

    @staticmethod
    def create_responsive_view(df):
        """Create a responsive view adjusting columns by screen size."""
        priority_columns = ['domain', 'dnssec_status', 'caa', 'dns_status']
        secondary_columns = ['cname_traversal', 'parent_caa']
        tertiary_columns = ['parent_dnssec_checks', 'ip_records']

        responsive_html = """
        <style>
            .responsive-table { width: 100%; border-collapse: collapse; }
            .responsive-table th, .responsive-table td { padding: 8px; text-align: left; border: 1px solid #ddd; }
            .responsive-table th { background-color: #4CAF50; color: white; }
            @media screen and (max-width: 1200px) { .tertiary-column { display: none; } }
            @media screen and (max-width: 800px) { .secondary-column { display: none; } }
            @media screen and (max-width: 500px) {
                .responsive-table th, .responsive-table td { padding: 4px; font-size: 12px; }
            }
        </style>
        <table class="responsive-table"><thead><tr>
        """

        all_columns = priority_columns + secondary_columns + tertiary_columns
        for col in all_columns:
            if col in df.columns:
                col_class = "tertiary-column" if col in tertiary_columns else ("secondary-column" if col in secondary_columns else "")
                responsive_html += f'<th class="{col_class}">{col}</th>'

        responsive_html += "</tr></thead><tbody>"

        for idx, row in df.iterrows():
            responsive_html += "<tr>"
            for col in all_columns:
                if col in df.columns:
                    col_class = "tertiary-column" if col in tertiary_columns else ("secondary-column" if col in secondary_columns else "")
                    responsive_html += f'<td class="{col_class}">{row[col]}</td>'
            responsive_html += "</tr>"

        responsive_html += """</tbody></table>
        <div style="margin-top: 10px; font-style: italic;">
            Note: Table columns automatically adjust based on screen size.
        </div>"""

        return HTML(responsive_html)


def setup_enhanced_ui():
    """Set up the enhanced UI for DNS checking."""
    global domains_text, output

    output = widgets.Output()
    DNSConfig.ensure_dirs()

    domains_text = widgets.Textarea(
        placeholder='Enter domains (one per line)\ne.g.:\nexample.com\ngoogle.com\nd2cmedia.ca',
        layout=widgets.Layout(width='50%', height='200px'),
        style={'background-color': '#333', 'color': 'white'}
    )

    run_button = widgets.Button(
        description='Check DNS Records',
        button_style='success',
        tooltip='Click to check DNS records for the domains',
        icon='check'
    )

    header = widgets.HTML(
        """<div style="background-color: #4CAF50; color: white; padding: 15px;
                      margin-bottom: 20px; border-radius: 5px;">
             <h2 style="margin: 0;">Enhanced DNS &amp; CAA Record Checker</h2>
             <p style="margin: 5px 0 0 0;">Check DNS configurations, DNSSEC status, and CAA records for multiple domains</p>
           </div>"""
    )

    instructions = widgets.HTML(
        """<div style="margin-bottom: 15px; padding: 10px; background-color: #333333;
                      color: #ffffff; border-radius: 5px; border: 1px solid #555555;">
             <h3 style="margin-top: 0; color: #ffffff;">Instructions:</h3>
             <ol style="color: #ffffff;">
               <li>Enter one domain per line in the text area below</li>
               <li>Click "Check DNS Records" to analyze configurations</li>
               <li>Use the filters to narrow down results</li>
               <li>Hover over cells to see full content</li>
               <li>Download results in CSV or HTML format</li>
             </ol>
           </div>"""
    )

    def run_enhanced_dns_checks_handler(b):
        output.clear_output()
        with output:
            try:
                if not domains_text.value.strip():
                    print("Please enter at least one domain to check.")
                    return

                domains = [
                    d.strip()
                    for d in domains_text.value.split('\n')
                    if d.strip() and not d.strip().startswith('#')
                ]

                if not domains:
                    print("No valid domains found. Please enter at least one valid domain.")
                    return

                results = UIUtils.run_dns_checks(domains, output)

                if results:
                    styler = DataFrameStyler(results['df'])
                    styled_df = styler.get_styled_df()
                    filter_widgets = UIComponents.create_filter_widgets(results['df'])
                    download_options = UIComponents.create_download_options(results['df'], styled_df)

                    display(filter_widgets['filters'])
                    display(download_options)
                    display(styled_df)

                    filter_widgets['output'] = output
                    print(f"\nDNS check completed! Detailed log saved to: {results['log_file']}")

            except Exception as e:
                import traceback
                print(f"Unexpected error: {e}")
                traceback.print_exc()

    run_button.on_click(run_enhanced_dns_checks_handler)

    display(header)
    display(instructions)
    display(domains_text)
    display(run_button)
    display(output)

    return {'domains_text': domains_text, 'run_button': run_button, 'output': output}
