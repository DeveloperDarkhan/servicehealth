import logging


def get_logger(log_file):
    """
    Creates and configures a logger for service diagnostics.

    Logic:
      - Creates a named logger "diagnostics".
      - Sets the logging level to INFO (all INFO and higher events will be logged).
      - Formats logs according to the README requirements:
        [YYYY-MM-DD HH:MM:SS] [LEVEL] - Message
      - Writes logs to the specified file (log_file).
      - Checks if a handler has already been added to avoid duplication on repeated calls.
      - Returns a ready logger object for use in all parts of the application.

    Args:
      log_file (str): Path to the file where diagnostic logs will be written.

    Returns:
      logging.Logger: Configured logger for centralized and standardized logging.
    """
    logger = logging.getLogger("diagnostics")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    # To avoid duplicating handlers on repeated calls
    if not logger.handlers:
        logger.addHandler(file_handler)
    return logger