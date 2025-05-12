import logging


def get_logger(log_file):
    logger = logging.getLogger("diagnostics")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    # Чтобы избежать дублирования хендлеров при повторном вызове
    if not logger.handlers:
        logger.addHandler(file_handler)
    return logger
