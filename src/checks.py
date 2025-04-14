#!/usr/bin/env python3

import os
import subprocess
import logging
import ldap

from ipalib import api
from ipalib import krb_utils
from ipapython import ipautil

class IPAChecker:
    """Class for performing various checks in IPA environment"""

    def __init__(self, logger=None, api_instance=None):
        """
        Initialize the checker

        Args:
            logger: Logger instance, if None - will use default logger
            api_instance: Existing IPA API instance, if None - will try to use global api
        """
        self.logger = logger or logging.getLogger('ipa-gpo-install')
        self.api = api_instance or api

    def check_kerberos_ticket(self):
        """
        Check if a valid Kerberos ticket exists

        Returns:
            True if a ticket exists and is valid, otherwise False
        """
        try:
            self.logger.debug("Checking for valid Kerberos ticket")
            principal = krb_utils.get_principal()

            if principal:
                self.logger.debug(f"Kerberos ticket exists for {principal}")
                return True
            else:
                self.logger.debug("Valid Kerberos ticket not found")
                return False

        except Exception as e:
            self.logger.debug(f"Error checking Kerberos ticket: {e}")
            return False