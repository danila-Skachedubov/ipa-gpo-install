from ipalib import api, errors
from ipalib import Str
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPQuery,
)
from ipalib import _, ngettext
from ipapython.dn import DN
from ipalib import Int, Str, Flag
import logging

logger = logging.getLogger(__name__)

register = Registry()

PLUGIN_CONFIG = (
    ('container_system', DN(('cn', 'System'))),
    ('container_grouppolicychain', DN(('cn', 'System'))),
)

OBJECT_TYPE_MAPPING = {
    'usergroup': ('group', 'cn'),
    'computergroup': ('hostgroup', 'cn'),
}

GP_LOOKUP_ATTRIBUTES = ['displayName', 'cn']


@register()
class chain(LDAPObject):
    """
    Group Policy Chain object.
    """
    container_dn = None
    object_name = _('Group Policy Chain')
    object_name_plural = _('Group Policy Chains')
    object_class = ['groupPolicyChain']
    permission_filter_objectclasses = ['groupPolicyChain']
    default_attributes = [
        'cn', 'displayName', 'userGroup', 'computerGroup', 'gpLink'
    ]
    allow_rename = True

    label = _('Group Policy Chains')
    label_singular = _('Group Policy Chain')

    managed_permissions = {
        'System: Read Group Policy Chains': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'displayname', 'usergroup',
                'computergroup', 'gplink'
            },
        },
        'System: Add Group Policy Chains': {
            'ipapermright': {'add'},
            'default_privileges': {'Group Policy Administrators'},
        },
        'System: Delete Group Policy Chains': {
            'ipapermright': {'delete'},
            'default_privileges': {'Group Policy Administrators'},
        },
        'System: Modify Group Policy Chains': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'cn', 'displayname', 'usergroup', 'computergroup', 'gplink'
            },
            'default_privileges': {'Group Policy Administrators'},
        },
    }

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Chain name'),
            doc=_('Group Policy Chain name'),
            primary_key=True,
            autofill=False,
        ),
        Str('displayname?',
            cli_name='display_name',
            label=_('Display name'),
            doc=_('Display name for the chain'),
        ),
        Str('usergroup?',
            cli_name='user_group',
            label=_('User group'),
            doc=_('User group name for this chain'),
        ),
        Str('computergroup?',
            cli_name='computer_group', 
            label=_('Computer group'),
            doc=_('Computer group name for this chain'),
        ),
        Str('gplink*',
            cli_name='gp_link',
            label=_('Group Policy links'),
            doc=_('List of Group Policy Container names'),
        ),
    )

    def _on_finalize(self):
        self.env._merge(**dict(PLUGIN_CONFIG))
        self.container_dn = self.env.container_grouppolicychain
        super(chain, self)._on_finalize()