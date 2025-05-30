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

    def find_gp_by_displayname(self, displayname):
        """Find Group Policy Container by displayName."""
        try:
            ldap = self.api.Backend.ldap2
            entry = ldap.find_entry_by_attr(
                'displayName',
                displayname,
                'groupPolicyContainer',
                base_dn=DN('cn=Policies,cn=System', api.env.basedn)
            )
            return entry.dn
        except errors.NotFound:
            raise errors.NotFound(
                reason=_("Group Policy '{}' not found").format(displayname)
            )

    def resolve_object_name(self, attr_name, name, strict=False):
        """Universal resolver for names to DN."""
        if name.startswith(('cn=', 'CN=')):
            return name
        try:
            if attr_name in OBJECT_TYPE_MAPPING:
                obj_type, name_attr = OBJECT_TYPE_MAPPING[attr_name]
                group_dn = self.api.Object[obj_type].get_dn(name)
                if strict:
                    ldap = self.api.Backend.ldap2
                    ldap.get_entry(group_dn, attrs_list=[name_attr])
                logger.debug("Resolved %s '%s' to DN", obj_type, name)
                return str(group_dn)
            elif attr_name == 'gplink':
                return str(self.find_gp_by_displayname(name))
            else:
                return name

        except errors.NotFound:
            if strict:
                obj_name = OBJECT_TYPE_MAPPING.get(attr_name, [attr_name])[0]
                raise errors.NotFound(
                    reason=_("{} '{}' not found").format(obj_name.title(), name)
                )
            logger.warning("Failed to resolve %s '%s': not found", attr_name, name)
            return name
        except Exception as e:
            if strict:
                obj_name = OBJECT_TYPE_MAPPING.get(attr_name, [attr_name])[0]
                raise errors.ValidationError(
                    name=attr_name,
                    error=_("Failed to resolve {} '{}': {}").format(obj_name, name, str(e))
                )
            logger.warning("Failed to resolve %s '%s': %s", attr_name, name, e)
            return name

    def convert_names_to_dns(self, options, strict=False):
        """Convert readable names to DNs for search/operations."""
        converted = {}

        for attr_name in OBJECT_TYPE_MAPPING:
            if attr_name in options and options[attr_name]:
                converted[attr_name] = self.resolve_object_name(
                    attr_name, options[attr_name], strict
                )
        if 'gplink' in options and options['gplink']:
            converted['gplink'] = self._convert_gp_names_to_dns(options['gplink'], strict)

        return converted

    def _convert_gp_names_to_dns(self, gp_names, strict=False):
        """Convert GP displayNames to DNs."""
        def resolve_gp(name):
            name = str(name)
            if name.startswith(('cn=', 'CN=')):
                return name
            try:
                return str(self.find_gp_by_displayname(name))
            except errors.NotFound:
                if strict:
                    raise
                logger.warning("Group Policy '%s' not found", name)
                return name

        # Always return a list for LDAP compatibility
        if isinstance(gp_names, str):
            return [resolve_gp(gp_names)]
        elif isinstance(gp_names, tuple):
            return list(map(resolve_gp, gp_names))
        else:
            return list(map(resolve_gp, gp_names))

    def convert_dns_to_names(self, ldap, entry_attrs):
        """Convert DNs to readable names in entry attributes."""

        for attr_name, (_, name_attr) in OBJECT_TYPE_MAPPING.items():
            if attr_name in entry_attrs and entry_attrs[attr_name]:
                dn_str = entry_attrs[attr_name][0]
                try:
                    dn_obj = DN(dn_str)
                    entry = ldap.get_entry(dn_obj, attrs_list=[name_attr])
                    entry_attrs[attr_name] = [entry[name_attr][0]]
                except errors.NotFound:
                    pass
                except Exception as e:
                    logger.warning("Error converting %s DN %s: %s", attr_name, dn_str, str(e))

        if 'gplink' in entry_attrs and entry_attrs['gplink']:
            gplink_display_names = []
            for gp_dn in entry_attrs['gplink']:
                try:
                    gp_dn_obj = DN(gp_dn)
                    gp_entry = ldap.get_entry(gp_dn_obj, attrs_list=GP_LOOKUP_ATTRIBUTES)

                    display_name = (
                        gp_entry.get('displayName', [None])[0] or
                        gp_entry.get('cn', [None])[0] or
                        gp_dn
                    )
                    gplink_display_names.append(display_name)

                except errors.NotFound:
                    gplink_display_names.append(gp_dn)
                except Exception as e:
                    logger.warning("Error processing gplink DN %s: %s", gp_dn, str(e))
                    gplink_display_names.append(gp_dn)

            entry_attrs['gplink'] = gplink_display_names

    def add_chain_to_gpmaster(self, chain_dn):
        """Add chain to GPMaster chain list."""
        try:
            ldap = self.api.Backend.ldap2
            gpmaster_dn = DN(('cn', 'grouppolicymaster'),
                           ('cn', 'etc'),
                           self.api.env.basedn)
            gpmaster_entry = ldap.get_entry(gpmaster_dn)
            current_chain_list = list(gpmaster_entry.get('chainList', []))
            chain_dn_str = str(chain_dn)

            if chain_dn_str not in current_chain_list:
                current_chain_list.append(chain_dn_str)
                gpmaster_entry['chainList'] = current_chain_list
                ldap.update_entry(gpmaster_entry)
                logger.info("Successfully added chain '%s' to GPMaster", chain_dn_str)
        except Exception as e:
            logger.error("Failed to add chain '%s' to GPMaster: %s",
                        chain_dn, str(e))