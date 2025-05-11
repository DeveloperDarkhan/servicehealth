from health_check.cli import parse_cli_args
from health_check.logger import get_logger
from health_check.checker import check_http
from health_check.diagnostics import run_basic_diagnostics, run_full_diagnostics

def main():
    args = parse_cli_args()
    logger = get_logger(args.log_file)    
    # Получаем домен из URL (например, из https://site.com/path -> site.com)
    domain = args.url.split('/')[2]
    result = check_http(args.url, args.keyword, args.timeout, logger)
    if not result:
        if args.full_diagnostics:
            logger.info("[CONFIG] - Full diagnostics mode enabled")
            run_full_diagnostics(domain, args.url, logger, args.timeout)
        else:
            run_basic_diagnostics(domain, args.url, logger, args.timeout)

if __name__ == "__main__":
    main()
