import os
import socket
import subprocess
import logging
from ipalib import api

logger = logging.getLogger('ipa-gpo-install')

def initialize_ipa_api():
    """
    Initialize the IPA API connection

    Returns:
        True if API initialization was successful, otherwise False
    """
    try:
        logger.debug("Initializing IPA API")
        api.bootstrap(context='cli')
        api.finalize()

        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        logger.info("IPA API initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize IPA API: {e}")
        return False

def check_kerberos_ticket():
    """
    Check if a valid Kerberos ticket exists

    Returns:
        True if a ticket exists and is valid, otherwise False
    """
    try:
        # Check for ticket using klist
        logger.debug("Checking for valid Kerberos ticket")
        result = subprocess.run(
            ["klist", "-s"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            logger.info("Kerberos ticket exists and is valid")
            return True
        else:
            logger.warning("Valid Kerberos ticket not found")
            return False

    except Exception as e:
        logger.error(f"Error checking Kerberos ticket: {e}")
        return False

def get_ipa_domain():
    """
    Get the IPA domain from API

    Returns:
        Domain name or None if not available
    """
    try:
        if not api.Backend.rpcclient.isconnected():
            if not initialize_ipa_api():
                return None

        logger.debug("Retrieving IPA domain")
        domain = api.env.domain
        logger.info(f"IPA domain: {domain}")
        return domain
    except Exception as e:
        logger.error(f"Failed to get IPA domain: {e}")
        return None