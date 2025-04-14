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