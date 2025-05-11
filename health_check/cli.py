import argparse

def parse_cli_args():
    parser = argparse.ArgumentParser(description="Service Health and Diagnostic Monitor")
    parser.add_argument('--url', required=True, help='URL for health check')
    parser.add_argument('--interval', type=int, default=60, help='Check interval (sec)')
    parser.add_argument('--timeout', type=int, default=10, help='HTTP timeout (sec)')
    parser.add_argument('--log-file', default='diagnostics.log', help='Log file path')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries')
    parser.add_argument('--keyword', default='Success', help='Keyword to search in response')
    parser.add_argument('--full-diagnostics', type=lambda x: x.lower() == 'true', default=False, help='Enable full diagnostics')
    return parser.parse_args()
