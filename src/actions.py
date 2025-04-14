#!/usr/bin/env python3


import os
import logging
import subprocess

from ipalib import api
from ipapython import ipautil
from ipaplatform.paths import paths

class IPAActions:
    """Class for performing actions in IPA environment"""

    def __init__(self, logger=None, api_instance=None):
        """
        Initialize the actions handler

        Args:
            logger: Logger instance, if None - will use default logger
            api_instance: Existing IPA API instance, if None - will try to use global api
        """
        self.logger = logger or logging.getLogger('ipa-gpo-install')
        self.api = api_instance or api

    def add_ldif_schema(self, ldif_file):
        """
        Add LDIF schema to LDAP using ipa-ldap-updater

        Args:
            ldif_file: Path to LDIF file

        Returns:
            True if successfully added, False otherwise
        """
        try:
            if not os.path.exists(ldif_file):
                self.logger.error(f"LDIF file not found: {ldif_file}")
                return False

            self.logger.info(f"Adding LDIF schema from file: {ldif_file}")
            cmd = ['/usr/sbin/ipa-ldap-updater', '-S', ldif_file]
            self.logger.debug(f"Running: {' '.join(cmd)}")
            result = ipautil.run(cmd, raiseonerr=False)

            if result.returncode == 0:
                self.logger.info(f"Successfully added schema from {ldif_file}")
                return True
            else:
                error_msg = result.error_output or "Unknown error"
                self.logger.error(f"Failed to add schema from {ldif_file}: {error_msg}")
                return False

        except Exception as e:
            self.logger.error(f"Error adding LDIF schema: {e}")
            return False

    def install_adtrust(self):
        """
        Install and configure AD Trust support

        Returns:
            True if installation was successful, False otherwise
        """
        try:
            self.logger.info("Installing AD Trust support")
            if not os.path.exists('/usr/sbin/ipa-adtrust-install'):
                self.logger.error("ipa-adtrust-install not found")
                return False
            cmd = ['/usr/sbin/ipa-adtrust-install', '-U']

            self.logger.debug(f"Running: {' '.join(cmd)}")
            result = ipautil.run(cmd, raiseonerr=False)

            if result.returncode != 0:
                self.logger.error(f"Failed to install AD Trust: {result.error_output}")
                return False
            self.logger.info("AD Trust installed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Error installing AD Trust: {e}")
            return False

    def create_sysvol_share(self):
        """
        Create SYSVOL Samba share

        Returns:
            True if creation was successful, False otherwise
        """
        try:
            sysvol_path = f"/var/lib/freeipa/sysvol/{self.api.env.domain}"
            self.logger.info(f"Creating SYSVOL share for: {sysvol_path}")

            if not os.path.exists(sysvol_path):
                self.logger.error(f"Cannot create share: directory {sysvol_path} does not exist")
                return False

            cmd = ["net", "conf", "addshare", "sysvol", sysvol_path, "writeable=y", "guest_ok=N"]
            self.logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                self.logger.error(f"Failed to create SYSVOL share: {result.stderr}")
                return False

            self.logger.info("SYSVOL share created successfully")
            return True

        except Exception as e:
            self.logger.error(f"Error creating SYSVOL share: {e}")
            return False
