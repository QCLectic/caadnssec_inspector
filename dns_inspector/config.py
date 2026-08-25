import os
import logging


class DNSConfig:
    """Centralized configuration for DNS checking."""

    # DNS resolution settings
    DEFAULT_TIMEOUT = 3.0
    DEFAULT_LIFETIME = 5.0
    DEFAULT_MAX_DEPTH = 5

    # Concurrency settings
    DEFAULT_MAX_WORKERS = 10

    # Public DNS nameservers to use
    DEFAULT_NAMESERVERS = [
        '1.1.1.1',         # Cloudflare
        '8.8.8.8',         # Google
        '9.9.9.9',         # Quad9
        '94.140.14.140',   # AdGuard
        '84.200.70.40'     # DNSWATCH
    ]

    # Record types to check
    DEFAULT_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'CAA', 'DNSKEY', 'DS']

    @staticmethod
    def ensure_dirs():
        """Ensure required directories exist."""
        dirs = ['logs', 'exports']
        for dir_name in dirs:
            os.makedirs(os.path.join(os.getcwd(), dir_name), exist_ok=True)
        return True

    @staticmethod
    def setup_logging(log_file='dns_checks.log'):
        """Set up logging configuration."""
        log_dir = os.path.join(os.getcwd(), 'logs')
        os.makedirs(log_dir, exist_ok=True)

        full_log_path = os.path.join(log_dir, log_file)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(full_log_path),
                logging.StreamHandler()
            ]
        )
        return full_log_path
