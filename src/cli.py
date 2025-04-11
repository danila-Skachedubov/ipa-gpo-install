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
            raise ScriptError("Must be root to setup Group Policy features on server")

        verbose, debug = options.debuglevel >= 1, options.debuglevel >= 2
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        standard_logging_setup(LOG_FILE_PATH, verbose=verbose, debug=debug, filemode='a')

        for log_module in ['ipalib', 'ipapython', 'ipaserver', 'ipaplatform']:
            logging.getLogger(log_module).setLevel(logging.CRITICAL)

        logger.info("Initializing IPA API...")
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