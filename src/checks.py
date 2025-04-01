#!/usr/bin/env python3

import os
import socket
import subprocess
import logging
from ipalib import api

class IPAChecker:
    """Class for performing various checks in IPA environment"""
    
    def __init__(self, logger=None):
        """
        Initialize the checker
        
        Args:
            logger: Logger instance, if None - will use default logger
        """
        self.logger = logger or logging.getLogger('ipa-gpo-install')
        self.ipa_connected = False
        self.domain = None
        self.fqdn = None

    def check_kerberos_ticket(self):
        """
        Check if a valid Kerberos ticket exists

        Returns:
            True if a ticket exists and is valid, otherwise False
        """
        try:
            self.logger.debug("Checking for valid Kerberos ticket")
            result = subprocess.run(
                ["klist", "-s"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                self.logger.info("Kerberos ticket exists and is valid")
                return True
            else:
                self.logger.warning("Valid Kerberos ticket not found")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking Kerberos ticket: {e}")
            return False
    
    def initialize_ipa_api(self):
        """
        Initialize the IPA API connection
        
        Returns:
            True if API initialization was successful, otherwise False
        """
        if self.ipa_connected:
            return True

        try:
            ipa_logger = logging.getLogger('ipa')
            original_level = ipa_logger.level
            ipa_logger.setLevel(logging.CRITICAL)
            
            self.logger.debug("Initializing IPA API")
            api.bootstrap(context='cli')
            api.finalize()            

            connected = False
            if not api.Backend.rpcclient.isconnected():
                api.Backend.rpcclient.connect()
                connected = api.Backend.rpcclient.isconnected()
            else:
                connected = True

            ipa_logger.setLevel(original_level)
            
            if connected:
                self.logger.info("IPA API initialized successfully")
                self.ipa_connected = True
                return True
            else:
                self.logger.error("Failed to connect to IPA API: connection not established")
                return False
        except Exception as e:
            self.logger.error(f"Failed to initialize IPA API: {e}")
            return False
    
    def get_ipa_domain(self):
        """
        Get the IPA domain from API
        
        Returns:
            Domain name or None if not available
        """
        if self.domain:
            return self.domain
            
        try:
            if not self.initialize_ipa_api():
                return None
                
            self.logger.debug("Retrieving IPA domain")
            self.domain = api.env.domain
            self.logger.info(f"IPA domain: {self.domain}")
            return self.domain
        except Exception as e:
            self.logger.error(f"Failed to get IPA domain: {e}")
            return None
    
    def check_ipa_services(self):
        """
        Check if all essential IPA services are running
        
        Returns:
            True if all essential services are running, otherwise False
        """

        domain = self.get_ipa_domain()
        if not domain:
            self.logger.error("Cannot determine domain name for services check")
            return False

        domain_suffix = domain.upper().replace('.', '-')

        services = [
            f'dirsrv@{domain_suffix}',
            'krb5kdc',
            'ipa'
        ]

        self.logger.debug("Checking IPA services")

        for service in services:
            try:
                cmd = ['systemctl', 'is-active', service]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    self.logger.error(f"Service {service} is not active")
                    return False
            except Exception as e:
                self.logger.error(f"Error checking service {service}")
                return False
        
        self.logger.info("All essential services are running")
        return True