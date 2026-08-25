import base64
import logging

import pandas as pd
from IPython.display import HTML
from tqdm.notebook import tqdm

from ..checker import DNSChecker
from ..config import DNSConfig


class UIUtils:
    """Utility functions for UI interactions and file handling."""

    @staticmethod
    def create_download_link(df, title="Download CSV", filename="dns_check_results.csv"):
        """Create downloadable link for DataFrame."""
        try:
            csv = df.to_csv(index=False)
            b64 = base64.b64encode(csv.encode())
            payload = b64.decode()
            html = f'<a download="{filename}" href="data:text/csv;base64,{payload}" target="_blank">{title}</a>'
            return HTML(html)
        except Exception as e:
            logging.error(f"Error creating download link: {e}")
            return HTML(f"Error creating download link: {e}")

    @staticmethod
    def export_html(styled_df, title="Download HTML", filename="dns_check_results.html"):
        """Create downloadable link for styled HTML table."""
        try:
            html_content = styled_df.to_html()

            expandable_css = """
            <style>
                td { max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; transition: all 0.3s; }
                td:hover { max-width: none !important; white-space: normal !important; overflow: visible !important; }
                .collapsible { cursor: pointer; background-color: #f1f1f1; margin: 5px 0; padding: 8px 15px;
                                width: 100%; border: none; text-align: left; outline: none; font-weight: bold; }
                .active, .collapsible:hover { background-color: #e0e0e0; }
                .content { padding: 0 18px; max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out;
                            background-color: #ffffff; }
            </style>
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    var coll = document.getElementsByClassName("collapsible");
                    for (var i = 0; i < coll.length; i++) {
                        coll[i].addEventListener("click", function() {
                            this.classList.toggle("active");
                            var content = this.nextElementSibling;
                            if (content.style.maxHeight) { content.style.maxHeight = null; }
                            else { content.style.maxHeight = content.scrollHeight + "px"; }
                        });
                    }
                });
            </script>
            """

            full_html = f"<html><head>{expandable_css}</head><body>{html_content}</body></html>"
            b64 = base64.b64encode(full_html.encode())
            payload = b64.decode()
            download_link = f'<a download="{filename}" href="data:text/html;base64,{payload}" target="_blank">{title}</a>'
            return HTML(download_link)
        except Exception as e:
            logging.error(f"Error creating HTML download link: {e}")
            return HTML(f"Error creating HTML download link: {e}")

    @staticmethod
    def run_dns_checks(domains, output_widget=None):
        """Run DNS checks for a list of domains with progress bar."""
        log_file = DNSConfig.setup_logging()
        checker = DNSChecker()

        logging.info(f"Starting DNS checks for {len(domains)} domain(s)")
        print(f"Checking DNS records for {len(domains)} domain(s)...")

        results = []

        with tqdm(total=len(domains), desc="DNS Checks", unit="domain") as pbar:
            for domain in domains:
                try:
                    result = checker.check_all_records(domain)
                    results.append(result)
                except Exception as e:
                    logging.error(f"Error checking {domain}: {e}")
                    results.append({
                        'domain': domain,
                        'dns_status': f'ERROR - {str(e)}',
                        'dnssec_enabled': 'Unknown',
                        'dnssec_issues': str(e)
                    })
                pbar.update(1)

        df = pd.DataFrame(results)
        return {'df': df, 'log_file': log_file}
