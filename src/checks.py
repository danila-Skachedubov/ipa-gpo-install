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

    def check_admin_privileges(self):
        """
        Check if current user has admin privileges

        Returns:
            True if user has admin privileges, otherwise False
        """
        try:
            principal = krb_utils.get_principal()
            if not principal:
                self.logger.error("No valid Kerberos principal found")
                return False
            username = principal.partition('@')[0].partition('/')[0]
            user = self.api.Command.user_show(username)['result']
            group = self.api.Command.group_show('admins')['result']

            has_admin = (user['uid'][0] in group['member_user'] and
                        group['cn'][0] in user['memberof_group'])

            if has_admin:
                self.logger.info(f"User {username} has admin privileges")
            else:
                self.logger.warning(f"User {username} does not have admin privileges")
            return has_admin

        except Exception as e:
            self.logger.error(f"Error checking admin privileges: {e}")
            return False

    def check_ipa_services(self):
        """
        Check if all essential IPA services are running

        Returns:
            True if all essential services are running, otherwise False
        """
        try:
            domain = self.api.env.domain
            if not domain:
                self.logger.error("Cannot determine domain name for services check")
                return False
            domain_suffix = domain.upper().replace('.', '-')

            services = [
                f'dirsrv@{domain_suffix}',
                'krb5kdc',
                'ipa',
                'sssd'
            ]
            self.logger.debug("Checking IPA services")

            for service in services:
                cmd = ['systemctl', 'is-active', service]
                self.logger.debug(f"Running: {' '.join(cmd)}")

                result = ipautil.run(cmd, raiseonerr=False)

                if result.returncode != 0:
                    self.logger.error(f"Service {service} is not active")
                    return False
                self.logger.debug(f"Service {service} is active")

            self.logger.info("All essential services are running")
            return True

        except Exception as e:
            self.logger.error(f"Error checking IPA services: {e}")
            return False

    def check_schema_complete(self, object_class_names):
        """
        Check if all required object classes exist in LDAP schema

        Args:
            object_class_names: List of object class names to check

        Returns:
            True if all classes exist, False if any is missing
        """
        try:
            conn = self.api.Backend.ldap2.conn

            self.logger.debug("Retrieving LDAP schema")
            try:
                schema_entry = conn.search_s('cn=schema', ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]
            except ldap.NO_SUCH_OBJECT:
                self.logger.debug('cn=schema not found, fallback to cn=subschema')
                schema_entry = conn.search_s('cn=subschema', ldap.SCOPE_BASE,
                    attrlist=['attributetypes', 'objectclasses'])[0]

            schema = ldap.schema.SubSchema(schema_entry[1])

            for class_name in object_class_names:
                if schema.get_obj(ldap.schema.ObjectClass, class_name) is None:
                    self.logger.debug(f"Object class '{class_name}' does not exist in schema")
                    return False

            self.logger.debug(f"All required object classes exist in schema")
            return True

        except Exception as e:
            self.logger.error(f"Error checking schema object classes: {e}")
            return False

    def check_adtrust_installed(self):
        """
        Check if AD Trust support is enabled in FreeIPA

        Returns:
            True if AD Trust is enabled, False otherwise
        """
        try:
            self.logger.debug("Checking if AD Trust is enabled")

            if not hasattr(self.api.Command, 'adtrust_is_enabled'):
                self.logger.error("AD Trust command not available")
                return False
            result = self.api.Command.adtrust_is_enabled()
            enabled = result.get('result', False)
            if enabled:
                self.logger.info("AD Trust is enabled")
            else:
                self.logger.warning("AD Trust is not enabled")

            return enabled

        except Exception as e:
            self.logger.error(f"Error checking AD Trust status: {e}")
            return False