Name:           ipa-gpo-install
Version:        0.0.1
Release:        alt1

Summary:        Prepare FreeIPA for Group Policy Management
License:        GPLv3+
Group:          System/Configuration/Other
Url:            https://github.com/danila-Skachedubov/ipa-gpo-install
BuildArch: noarch

BuildRequires: rpm-build-python3
BuildRequires: gettext-tools

Requires: freeipa-server
Requires: freeipa-server-trust-ad
Source0: %name-%version.tar

%description
A utility for preparing FreeIPA for Group Policy Management.
Extends the LDAP schema with Group Policy related object classes
and creates the necessary directory structure.

%prep
%setup -q

%build
cd locale/ru/LC_MESSAGES/
msgfmt ipa-gpo-install.po -o ipa-gpo-install.mo

%install
mkdir -p %buildroot%_bindir
mkdir -p %buildroot%_datadir/%name/data
mkdir -p %buildroot%python3_sitelibdir/ipa_gpo_install
mkdir -p %buildroot%_datadir/locale/ru/LC_MESSAGES
mkdir -p %buildroot%_mandir/man8
mkdir -p %buildroot%_mandir/ru/man8
mkdir -p %buildroot%_datadir/bash-completion/completions

install -m 755 bin/ipa-gpo-install %buildroot%_bindir/
cp -a ipa_gpo_install/* %buildroot%python3_sitelibdir/ipa_gpo_install/
install -m 644 data/74alt-group-policy.ldif %buildroot%_datadir/%name/data/
install -m 644 locale/ru/LC_MESSAGES/ipa-gpo-install.mo %buildroot%_datadir/locale/ru/LC_MESSAGES/
install -m 644 doc/ipa-gpo-install.8 %buildroot%_mandir/man8/
install -m 644 doc/ru/ipa-gpo-install.8 %buildroot%_mandir/ru/man8/
install -m 644 completions/ipa-gpo-install %buildroot%_datadir/bash-completion/completions/

%files
%doc README.md
%_bindir/ipa-gpo-install
%python3_sitelibdir/ipa_gpo_install
%_datadir/%name
%_datadir/locale/ru/LC_MESSAGES/%name.mo
%_mandir/man8/ipa-gpo-install.8*
%_mandir/ru/man8/ipa-gpo-install.8*
%_datadir/bash-completion/completions/ipa-gpo-install

%changelog
* Wed Apr 16 2025 Danila Skachedubov <skachedubov@altlinux.org> 0.0.1-alt1
- Initial build