#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging

from ipapython.config import IPAOptionParser
from ipapython.admintool import ScriptError, admin_cleanup_global_argv
from ipapython import version
from ipalib import api, errors, krb_utils
from ipapython.ipa_log_manager import standard_logging_setup
from ipaplatform.paths import paths
from ipaserver.install.installutils import run_script

# Import our modules
from src.checks import IPAChecker

# Logger setup
logger = logging.getLogger(os.path.basename(__file__))
log_file_name = '/var/log/freeipa/ipa-gpo-install.log'

def parse_options():
    """
    Parse command line arguments
    
    Returns:
        Tuple of (safe_options, options)
    """
    parser = IPAOptionParser(version=version.VERSION)
    parser.add_option("--debuglevel", type="int", dest="debuglevel",
                      default=0, metavar="LEVEL",
                      help="Debug level: 0=errors, 1=warnings, 2=debug")
    parser.add_option("--check-only", dest="check_only", action="store_true",
                      default=False, help="Only perform checks without making changes")
    parser.add_option("--force", dest="force", action="store_true",
                      default=False, help="Force operations despite warnings (use with caution)")
    
    options, _args = parser.parse_args()
    safe_options = parser.get_safe_opts(options)
    admin_cleanup_global_argv(parser, options, sys.argv)
    
    return safe_options, options

def main():
    """
    Main entry point for the application
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """

    safe_options, options = parse_options()
    
    # Check if running as root
    if os.getegid() != 0:
        raise ScriptError("Must be root to setup Group Policy features on server")
    
    verbose = options.debuglevel >= 1
    debug = options.debuglevel >= 2
    standard_logging_setup(log_file_name, verbose=verbose, debug=debug, filemode='a')
    print(f"The log file for this installation can be found in {log_file_name}")

    for log_module in ['ipalib', 'ipapython', 'ipaserver', 'ipaplatform']:
        logging.getLogger(log_module).setLevel(logging.CRITICAL)

    logger.info("Initializing IPA API...")
    api.bootstrap(
        in_server=True,
        debug=False,
        context='installer',
        confdir=paths.ETC_IPA
    )
    api.finalize()
    

    try:
        api.Backend.ldap2.connect()
        logger.info("Connected to LDAP server")
    except errors.ACIError:
        raise ScriptError(
            "Outdated Kerberos credentials. Use kdestroy and kinit to update your ticket")
    except errors.DatabaseError:
        raise ScriptError(
            "Cannot connect to the LDAP database. Please check if IPA is running")
    
    # Create checker instance with existing API
    checker = IPAChecker(logger, api)
    
    # Check admin privileges
    try:
        principal = krb_utils.get_principal()
        logger.info(f"Using Kerberos principal: {principal}")
        
        user = api.Command.user_show(
            principal.partition('@')[0].partition('/')[0])['result']
        group = api.Command.group_show(u'admins')['result']
        if not (user['uid'][0] in group['member_user'] and
                group['cn'][0] in user['memberof_group']):
            raise errors.RequirementError(name='admins group membership')
        logger.info("Verified admin privileges")
    except errors.CCacheError as e:
        raise ScriptError(f"Must have Kerberos credentials: {e}")
    except errors.RequirementError:
        raise ScriptError(
            "Must have administrative privileges to setup Group Policy features")
    except Exception as e:
        raise ScriptError(f"Error checking admin rights: {e}")
    
    # Run checks
    logger.info("Performing environment checks...")
    
    # Check IPA services
    logger.info("Checking IPA services...")
    services_running = checker.check_ipa_services()
    if not services_running:
        logger.error("Not all essential services are running")
        if not options.force:
            return 1
        logger.warning("Continuing despite service issues (--force specified)")
    
    # Check LDAP schema for required object classes
    logger.info("Checking LDAP schema for required object classes...")
    required_classes = ['altOrganizationalUnit', 'groupPolicyContainer']
    object_classes = checker.check_schema_object_classes(required_classes)
    
    all_classes_exist = all(object_classes.values())
    
    if all_classes_exist:
        logger.info("All required object classes already exist in schema")
    else:
        missing_classes = [name for name, exists in object_classes.items() if not exists]
        logger.info(f"Missing object classes: {', '.join(missing_classes)}")
        
        if options.check_only:
            logger.info("Check-only mode: schema changes would be needed")
        else:
            logger.info("Schema changes are needed, proceeding...")
            
            # Add schema from LDIF file
            ldif_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                     'data', 'gpo-schema.ldif')
            
            if not os.path.exists(ldif_file):
                logger.error(f"LDIF file not found: {ldif_file}")
                return 1
                
            result = checker.add_ldif_schema(ldif_file)
            if not result:
                logger.error("Failed to add schema")
                return 1
                
            logger.info("Schema successfully extended")


    # Check and configure CIFS service
    logger.info("Checking and configuring CIFS service...")
    cifs_service_ok = checker.ensure_cifs_service()
    if not cifs_service_ok:
        logger.error("Failed to configure CIFS service")
        if not options.force:
            return 1
        logger.warning("Continuing despite CIFS configuration issues (--force specified)")



    # For check-only mode, stop here
    if options.check_only:
        logger.info("Check-only mode: all checks completed")
        return 0
    # For check-only mode, stop here
    if options.check_only:
        logger.info("Check-only mode: all checks completed successfully")
        return 0
    
    print("""
=============================================================================
Setup complete

The IPA LDAP schema has been extended with Group Policy related object classes.
You can now proceed with Group Policy configuration.

=============================================================================
""")
    
    # Disconnect from LDAP
    api.Backend.ldap2.disconnect()
    
    return 0

if __name__ == '__main__':
    run_script(
        main,
        log_file_name=log_file_name,
        operation_name='ipa-gpo-install')