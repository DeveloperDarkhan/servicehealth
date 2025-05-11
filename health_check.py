from health_check.cli import parse_cli_args
from health_check.checker import check_http, verify_dns
from health_check.logger import get_logger
from health_check.diagnostics import run_basic_diagnostics, run_full_diagnostics

def main():
    args = parse_cli_args()
    domain = args.url.split('/')[2]
    logger = get_logger(args.log_file)

    checkdomain = verify_dns(domain, logger)

    if checkdomain:
        checkhttp = check_http(domain, args.url, args.keyword, args.timeout, logger)
        if not checkhttp:
            if args.full_diagnostics:
                logger.info("[CONFIG] - Full diagnostics mode enabled")
                run_full_diagnostics(domain, args.url, logger, args.timeout)
            else:
                run_basic_diagnostics(domain, args.url, logger, args.timeout)

if __name__ == "__main__":
    main()
