import logging
import sys

LOG_LEVELS = {
    0: logging.ERROR,    # Errors only
    1: logging.WARNING,  # Warnings and errors
    2: logging.DEBUG     # Everything, including debug information
}

def setup_logger(verbose_level=0):
    """
    Set up the logging system.
    
    Args:
        verbose_level: Verbosity level (0-2)
        log_file: Path to the log file
        
    Returns:
        Configured logger
    """

    if verbose_level > 2:
        verbose_level = 2

    logger = logging.getLogger('ipa-gpo-install')
    logger.setLevel(LOG_LEVELS.get(verbose_level, logging.ERROR))

    if logger.handlers:
        logger.handlers = []

    console_formatter = logging.Formatter('%(levelname)s: %(message)s')

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger