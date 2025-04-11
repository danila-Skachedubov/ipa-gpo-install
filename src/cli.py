#!/usr/bin/env python3

import os
import sys
import logging
from typing import Dict, Tuple, List, Any, Callable

from ipapython.config import IPAOptionParser
from ipapython.admintool import ScriptError, admin_cleanup_global_argv
from ipapython import version
from ipalib import api, errors
from ipapython.ipa_log_manager import standard_logging_setup
from ipaplatform.paths import paths
from ipaserver.install.installutils import run_script

from src.checks import IPAChecker
from src.actions import IPAActions


LOG_FILE_PATH = '/var/log/freeipa/ipa-gpo-install.log'
SCHEMA_LDIF_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'data', '74alt-group-policy.ldif'
)
REQUIRED_SCHEMA_CLASSES = ['altOrganizationalUnit', 'groupPolicyContainer']

logger = logging.getLogger(os.path.basename(__file__))

def parse_options() -> Tuple[Dict, Any]:
    """Parse command line arguments"""
    parser = IPAOptionParser(version=version.VERSION)
    parser.add_option("--debuglevel", type="int", dest="debuglevel",
                      default=0, metavar="LEVEL",
                      help="Debug level: 0=errors, 1=warnings, 2=debug")
    parser.add_option("--check-only", dest="check_only", action="store_true",
                      default=False, help="Only perform checks without making changes")
    
    options, _args = parser.parse_args()
    safe_options = parser.get_safe_opts(options)
    admin_cleanup_global_argv(parser, options, sys.argv)

    return safe_options, options

def setup_environment(options: Any) -> bool:
    """Set up environment and initialize API"""
    try:
        if os.geteuid() != 0:
            logger.error("Must be root to setup Group Policy features on server")
            return False

        verbose, debug = options.debuglevel >= 1, options.debuglevel >= 2
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        standard_logging_setup(LOG_FILE_PATH, verbose=verbose, debug=debug, filemode='a')

        for log_module in ['ipalib', 'ipapython', 'ipaserver', 'ipaplatform']:
            logging.getLogger(log_module).setLevel(logging.CRITICAL)

        logger.info("Initializing IPA API")
        api.bootstrap(in_server=True, debug=False, context='installer', confdir=paths.ETC_IPA)
        api.finalize()

        try:
            api.Backend.ldap2.connect()
            logger.info("Connected to LDAP server")
            return True
        except errors.DatabaseError:
            raise ScriptError("Cannot connect to the LDAP database. Please check if IPA is running")

    except Exception as e:
        logger.error(f"Error setting up environment: {e}")
        return False

def check_critical_requirements(checker: IPAChecker) -> bool:
    """Check critical requirements that must be met before proceeding"""

    logger.info("Checking Kerberos ticket")
    if not checker.check_kerberos_ticket():
        logger.error("Missing Kerberos ticket. Run 'kinit' to obtain a valid ticket.")
        return False

    logger.info("Checking admin privileges...")
    if not checker.check_admin_privileges():
        logger.error("Administrative privileges required.")
        return False

    logger.info("Checking IPA services...")
    if not checker.check_ipa_services():
        logger.error("Essential IPA services are not running.")
        return False

    return True

def perform_configuration_checks(checker: IPAChecker) -> Dict[str, Any]:
    """Perform non-critical checks to determine what actions are needed"""
    results = {}

    logger.info("Checking LDAP schema for required object classes...")
    results['schema_complete'] = checker.check_schema_complete(REQUIRED_SCHEMA_CLASSES)

    logger.info("Checking if AD Trust is enabled...")
    results['adtrust_enabled'] = checker.check_adtrust_installed()

    logger.info("Checking SYSVOL directory and share...")
    results['sysvol_directory'] = checker.check_sysvol_directory()
    results['sysvol_share'] = checker.check_sysvol_share()

    return results

def execute_required_actions(actions: IPAActions, check_results: Dict[str, Any]) -> bool:
    """Execute required actions based on check results"""
    tasks = []
    
    if not check_results['schema_complete']:
        tasks.append(("Extend LDAP schema", actions.add_ldif_schema, SCHEMA_LDIF_PATH))

    if not check_results['adtrust_enabled']:
        tasks.append(("Install AD Trust", actions.install_adtrust))

    if not check_results['sysvol_directory']:
        tasks.append(("Create SYSVOL directory", actions.create_sysvol_directory))

    if not check_results['sysvol_share']:
        tasks.append(("Create SYSVOL share", actions.create_sysvol_share))

    for task in tasks:
        if not run_task(*task):
            return False

    return True


def main():
    """Main entry point for the application"""

    safe_options, options = parse_options()
    if not setup_environment(options):
        return 1
    try:
        checker = IPAChecker(logger, api)
        logger.info("Checking critical requirements")
        if not check_critical_requirements(checker):
            return 1

        logger.info("Performing configuration environment checks")
        check_results = perform_configuration_checks(checker)
 
        if options.check_only:
            logger.info("Check-only mode: all checks completed")
            return 0

        actions = IPAActions(logger, api)
        if not execute_required_actions(actions, check_results):
            return 1

        print("""
=============================================================================
Setup complete

The IPA LDAP schema has been extended with Group Policy related object classes.
You can now proceed with Group Policy configuration.
=============================================================================
""")

        return 0
    finally:
        if api.Backend.ldap2.isconnected():
            api.Backend.ldap2.disconnect()


if __name__ == '__main__':
    run_script(main, log_file_name=LOG_FILE_PATH, operation_name='ipa-gpo-install')