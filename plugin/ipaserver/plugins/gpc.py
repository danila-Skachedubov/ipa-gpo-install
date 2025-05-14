from ipalib import api, errors
from ipalib import Str, Int, Command
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
)
from ipalib import _, ngettext
from ipapython.dn import DN
import uuid
import dbus
import dbus.mainloop.glib
import logging
from ipapython.ipautil import run

logger = logging.getLogger(__name__)

register = Registry()

PLUGIN_CONFIG = (
    ('container_system', DN(('cn', 'System'))),
    ('container_grouppolicy', DN(('cn', 'Policies'), ('cn', 'System'))),
)


@register()
class grouppolicy(LDAPObject):
    """
    Group Policy Object.
    """
    container_dn = None
    object_name = _('Group Policy Object')
    object_name_plural = _('Group Policy Objects')
    object_class = ['groupPolicyContainer']
    permission_filter_objectclasses = ['groupPolicyContainer']
    default_attributes = [
        'cn', 'displayName', 'distinguishedName', 'flags',
        'gPCFileSysPath', 'versionNumber',
    ]
    search_display_attributes = [
        'cn', 'displayName', 'flags', 'versionNumber',
    ]
    uuid_attribute = 'cn'
    allow_rename = False

    managed_permissions = {
        'System: Read Group Policy Objects': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'displayName', 'distinguishedName', 'flags',
                'objectclass',
            },
        },
        'System: Read Group Policy Objects Content': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'read'},
            'ipapermdefaultattr': {
                'gPCFileSysPath', 'versionNumber'
            },
            'default_privileges': {'Group Policy Administrators'},
        },
        'System: Add Group Policy Objects': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'add'},
            'default_privileges': {'Group Policy Administrators'},
        },
        'System: Modify Group Policy Objects': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'displayName', 'flags',
                'gPCFileSysPath', 'versionNumber',
            },
            'default_privileges': {'Group Policy Administrators'},
        },
        'System: Remove Group Policy Objects': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'delete'},
            'default_privileges': {'Group Policy Administrators'},
        },
    }

    label = _('Group Policy Objects')
    label_singular = _('Group Policy Object')

    takes_params = (
        Str('displayname',
            label=_('Policy name'),
            doc=_('Group Policy Object display name'),
            primary_key=True,
        ),
        Str('cn?',
            label=_('Policy GUID'),
            doc=_('Group Policy Object GUID'),
            flags=['no_create', 'no_update', 'no_search', 'no_option', 'no_output'],
        ),
        Str('distinguishedname?',
            label=_('Distinguished Name'),
            doc=_('Distinguished name of the group policy object'),
            flags=['no_create', 'no_update', 'no_search', 'no_output'],
        ),
        Int('flags?',
            label=_('Flags'),
            doc=_('Group Policy Object flags'),
            default=0,
            flags=['no_create', 'no_update'],
        ),
        Str('gpcfilesyspath?',
            label=_('File system path'),
            doc=_('Path to policy files on the file system'),
            flags=['no_create', 'no_update'],
        ),
        Int('versionnumber?',
            label=_('Version number'),
            doc=_('Version number of the policy'),
            default=0,
            minvalue=0,
            flags=['no_create', 'no_update'],
        ),
    )

    def _on_finalize(self):
        self.env._merge(**dict(PLUGIN_CONFIG))
        self.container_dn = self.env.container_grouppolicy
        super(grouppolicy, self)._on_finalize()


@register()
class grouppolicy_add(LDAPCreate):
    __doc__ = _('Create a new Group Policy Object.')
    msg_summary = _('Added Group Policy Object "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        displayname = keys[-1]
        try:
            ldap.find_entry_by_attr(
                'displayName',
                displayname,
                'groupPolicyContainer',
                base_dn=DN(api.env.container_grouppolicy, api.env.basedn)
            )
            raise errors.InvocationError(
                message=_('A Group Policy Object with displayName "%s" already exists.') % displayname
            )
        except errors.NotFound:
            pass

        guid = '{' + str(uuid.uuid4()).upper() + '}'
        dn = DN(('cn', guid), api.env.container_grouppolicy, api.env.basedn)
        entry_attrs['cn'] = guid
        entry_attrs['distinguishedname'] = str(dn)
        entry_attrs['gpcfilesyspath'] = f"\\\\{api.env.domain}\\SysVol\\{api.env.domain}\\Policies\\{guid}"
        entry_attrs['flags'] = 0
        entry_attrs['versionnumber'] = 0

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        guid = str(dn[0].value)
        domain = api.env.domain.lower()

        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        params = [guid, domain]
        while len(params) < 2:
            params.append('')

        try:
            bus = dbus.SystemBus()
            obj = bus.get_object('org.freeipa.server', '/',
                                follow_name_owner_changes=True)
            server = dbus.Interface(obj, 'org.freeipa.server')

            ret, stdout, stderr = server.create_gpo_structure(*params)

            if ret != 0:
                logger.error("Failed to create GPO structure: %s", stderr)
                raise errors.ExecutionError(
                    message=_('Failed to create GPO structure: %(error)s')
                            % {'error': stderr or _('Unknown error')}
                )

        except dbus.DBusException as e:
            logger.error('Failed to call DBus: %s', str(e))
            raise errors.ExecutionError(
                message=_('Failed to communicate with DBus service')
            )

        return dn