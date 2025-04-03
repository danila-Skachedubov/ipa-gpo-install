#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import subprocess

# FreeIPA dependencies
from ipalib import api, errors
from ipalib import krb_utils
from ipapython import ipautil
from ipaplatform.paths import paths
import ldap

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
        self.ipa_connected = (self.api is not None and 
                             hasattr(self.api.Backend, 'ldap2') and 
                             self.api.Backend.ldap2.isconnected())
        self.smb_conf = paths.SMB_CONF
        self.fqdn =  api.env.host
        self.domain = api.env.realm


    def check_kerberos_ticket(self):
        """
        Check if a valid Kerberos ticket exists
        
        Returns:
            True if a ticket exists and is valid, otherwise False
        """
        try:
            self.logger.debug("Checking for valid Kerberos ticket")
            
            # Use krb_utils to get principal
            principal = krb_utils.get_principal()
            
            if principal:
                self.logger.info(f"Kerberos ticket exists for {principal}")
                return True
            else:
                self.logger.warning("Valid Kerberos ticket not found")
                return False
                
        except Exception as e:
            self.logger.error(f"Error checking Kerberos ticket: {e}")
            return False
    
    def check_ipa_services(self):
        """
        Check if all essential IPA services are running
        
        Returns:
            True if all essential services are running, otherwise False
        """
        # Get domain for dirsrv service name
        domain = self.domain
        if not domain:
            self.logger.error("Cannot determine domain name for services check")
            return False
        
        # Format domain for service name (uppercase and replace dots with dashes)
        domain_suffix = domain.upper().replace('.', '-')
        
        # Essential services
        services = [
            f'dirsrv@{domain_suffix}',
            'krb5kdc',
            'ipa'
        ]
        
        self.logger.debug("Checking IPA services")
        
        # Check each service
        for service in services:
            try:
                cmd = ['systemctl', 'is-active', service]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    self.logger.error(f"Service {service} is not active")
                    return False
                self.logger.debug(f"Service {service} is active")
            except Exception as e:
                self.logger.error(f"Error checking service {service}: {e}")
                return False
        
        self.logger.info("All essential services are running")
        return True

    def check_schema_object_classes(self, object_class_names):
        """
        Check if specific object classes exist in LDAP schema
        
        Args:
            object_class_names: List of object class names to check
            
        Returns:
            Dict mapping object class names to boolean (True if exists, False if not)
        """
        result = {name: False for name in object_class_names}
        
        try:
            # Make sure LDAP connection is available
            if not hasattr(self.api.Backend, 'ldap2') or not self.api.Backend.ldap2.isconnected():
                self.logger.error("LDAP connection not available")
                return result
            
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
                oc_exists = schema.get_obj(ldap.schema.ObjectClass, class_name) is not None
                result[class_name] = oc_exists
                
                if oc_exists:
                    self.logger.info(f"Object class '{class_name}' already exists in schema")
                else:
                    self.logger.info(f"Object class '{class_name}' does not exist in schema")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error checking schema object classes: {e}")
            return result


    def ensure_cifs_service(self):
        """
        Ensure CIFS service exists and has proper keytab
        
        Returns:
            True if service exists and keytab is valid, False otherwise
        """
        try:
            self.logger.debug("Checking and configuring CIFS service")

            # Construct principal name
            principal = f"cifs/{self.fqdn}@{self.domain}"
            service_name = f"cifs/{self.fqdn}"
            
            self.logger.debug(f"Service principal: {principal}")
            
            # Check if service already exists
            try:
                self.api.Command.service_show(service_name)
                self.logger.info(f"CIFS service {service_name} already exists")
                service_exists = True
            except errors.NotFound:
                self.logger.info(f"CIFS service {service_name} not found, will create it")
                service_exists = False
            
            # Create service if it doesn't exist
            if not service_exists:
                try:
                    result = self.api.Command.service_add(service_name, force=True)
                    self.logger.info(f"CIFS service {service_name} created successfully")
                except Exception as e:
                    self.logger.error(f"Failed to create CIFS service: {e}")
                    return False
            
            # Now ensure the keytab file exists with proper keys
            keytab_file = paths.SAMBA_KEYTAB
            
            # Use IPA's ipa-getkeytab to retrieve the keytab
            
            args = [
                paths.IPA_GETKEYTAB,
                "-s", self.api.env.server,
                "-p", principal,
                "-k", keytab_file,
                "-e", "aes128-cts-hmac-sha1-96,aes256-cts-hmac-sha1-96,arcfour-hmac"
            ]
            
            try:
                self.logger.debug(f"Running: {' '.join(args)}")
                ipautil.run(args)
                self.logger.info(f"Keytab generated successfully for {principal}")
                
                # Set proper permissions
                os.chmod(keytab_file, 0o640)
                
                # Set ipaNTHash attribute
                value = "ipaNTHash=MagicRegen"
                try:
                    self.api.Command.service_mod(service_name, addattr=value)
                    self.logger.info(f"NT hash updated for {service_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to update NT hash for {service_name}: {e}")
                    # Not critical, continue
                
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to generate keytab: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error configuring CIFS service: {e}")
            return False