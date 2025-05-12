import argparse


def parse_cli_args():
    """
    Parses command-line arguments for the Service Health and Diagnostic Monitor.

    Logic:
      - Supports all required and optional CLI parameters described in Usage and Feature List.
      - Requires a URL for health check; other parameters have default values.
      - Allows control over timeouts, logging, number of retries, keyword for successful check, and toggling advanced diagnostics mode.
      - Returns an object with parsed arguments for further monitoring and diagnostics.

    Command-line arguments:
      --url             (str, required) — URL for service health check.
      --interval        (int, default 60) — Interval between checks in seconds.
      --timeout         (int, default 10) — HTTP request timeout in seconds.
      --log-file        (str, default diagnostics.log) — Path to the log file.
      --retries         (int, default 3) — Number of retries on failure.
      --keyword         (str, default "Success") — Keyword to search for in the response.
      --full-diagnostics (bool, default False) — Flag to enable advanced diagnostics (see Diagnostic Requirements).

    Returns:
      Namespace: argparse object with fields for all parameters.
    """
    parser = argparse.ArgumentParser(
        description="Service Health and Diagnostic Monitor"
    )
    parser.add_argument("--url", required=True, help="URL for health check")
    parser.add_argument("--interval", type=int, default=60, help="Check interval (sec)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout (sec)")
    parser.add_argument("--log-file", default="diagnostics.log", help="Log file path")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries")
    parser.add_argument(
        "--keyword", default="Success", help="Keyword to search in response"
    )
    parser.add_argument(
        "--full-diagnostics",
        type=lambda x: x.lower() == "true",
        default=False,
        help="Enable full diagnostics",
    )
    return parser.parse_args()
