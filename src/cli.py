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