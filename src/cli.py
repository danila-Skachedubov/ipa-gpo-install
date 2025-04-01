import os
import logging
import sys
import argparse
from .checks import initialize_ipa_api, get_ipa_domain
from .logger import setup_logger

def parse_args():
    """
    Parse command line arguments

    Returns:
        Parsed arguments object
    """
    parser = argparse.ArgumentParser(
        description="Utility for preparing FreeIPA for Group Policy Management"
    )

    parser.add_argument('--debuglevel', type=int, choices=[0, 1, 2], default=0,
                        help='Debug level: 0=errors only, 1=warnings, 2=debug')
    parser.add_argument('--check-only', action='store_true',
                        help='Only perform checks without making changes')

    return parser.parse_args()

def main():
    """
    Main entry point for the application

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    logger = logging.getLogger('ipa-gpo-install')
    args = parse_args()
    logger = setup_logger(args.debuglevel)


    logger.info("Starting ipa-gpo-install")
    if args.check_only:
        logger.info("Running in check-only mode")
        if initialize_ipa_api():
            logger.info("IPA API connection successful")

            domain = get_ipa_domain()
            if domain:
                logger.info(f"IPA domain: {domain}")
            else:
                logger.error("Failed to retrieve IPA domain")
                return 1
        else:
            logger.error("Failed to connect to IPA API")
            return 1

        return 0

    logger.info("Operation completed successfully")
    return 0

if __name__ == '__main__':
    sys.exit(main())
