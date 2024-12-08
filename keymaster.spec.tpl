Name:           keymaster
Version:        {{VERSION}}
Release:        1%{?dist}
Summary:        Short term access certificate generator and client

#Group:
License:        ASL 2.0
URL:            https://github.com/cviecco/simple-cloud-encrypt/
Source0:        keymaster-%{version}.tar.gz

#BuildRequires: golang
#Requires:
Requires(pre): /usr/sbin/useradd, /usr/bin/getent
Requires(postun): /usr/sbin/userdel

#no debug package as this is go
%define debug_package %{nil}

%description
Simple utilites for checking state of ldap infrastructure


%prep
%setup -n %{name}-%{version}


%build
make build


%install
#%make_install
%{__install} -Dp -m0755 bin/keymasterd %{buildroot}%{_sbindir}/keymasterd
%{__install} -Dp -m0755 bin/keymaster %{buildroot}%{_bindir}/keymaster
%{__install} -Dp -m0755 bin/keymaster-unlocker %{buildroot}%{_bindir}/keymaster-unlocker
install -d %{buildroot}/usr/lib/systemd/system
install -p -m 0644 misc/startup/keymaster.service %{buildroot}/usr/lib/systemd/system/keymaster.service
install -d %{buildroot}/%{_datarootdir}/keymasterd/static_files/
install -p -m 0644 cmd/keymasterd/static_files/u2f-api.js  %{buildroot}/%{_datarootdir}/keymasterd/static_files/u2f-api.js
install -p -m 0644 cmd/keymasterd/static_files/keymaster-u2f.js  %{buildroot}/%{_datarootdir}/keymasterd/static_files/keymaster-u2f.js
install -p -m 0644 cmd/keymasterd/static_files/keymaster-webauthn.js %{buildroot}/%{_datarootdir}/keymasterd/static_files/keymaster-webauthn.js
install -p -m 0644 cmd/keymasterd/static_files/webui-2fa-u2f.js  %{buildroot}/%{_datarootdir}/keymasterd/static_files/webui-2fa-u2f.js
install -p -m 0644 cmd/keymasterd/static_files/webui-2fa-okta-push.js %{buildroot}/%{_datarootdir}/keymasterd/static_files/webui-2fa-okta-push.js
install -p -m 0644 cmd/keymasterd/static_files/webui-2fa-symc-vip.js  %{buildroot}/%{_datarootdir}/keymasterd/static_files/webui-2fa-symc-vip.js
install -p -m 0644 cmd/keymasterd/static_files/keymaster.css  %{buildroot}/%{_datarootdir}/keymasterd/static_files/keymaster.css
install -p -m 0644 cmd/keymasterd/static_files/jquery-3.7.1.min.js %{buildroot}/%{_datarootdir}/keymasterd/static_files/jquery-3.7.1.min.js
install -p -m 0644 cmd/keymasterd/static_files/favicon.ico %{buildroot}/%{_datarootdir}/keymasterd/static_files/favicon.ico
install -d %{buildroot}/%{_datarootdir}/keymasterd/customization_data/templates
install -p -m 0644 cmd/keymasterd/customization_data/templates/header_extra.tmpl %{buildroot}/%{_datarootdir}/keymasterd/customization_data/templates/header_extra.tmpl
install -p -m 0644 cmd/keymasterd/customization_data/templates/footer_extra.tmpl %{buildroot}/%{_datarootdir}/keymasterd/customization_data/templates/footer_extra.tmpl
install -p -m 0644 cmd/keymasterd/customization_data/templates/login_extra.tmpl %{buildroot}/%{_datarootdir}/keymasterd/customization_data/templates/login_extra.tmpl
install -d %{buildroot}/%{_datarootdir}/keymasterd/customization_data/web_resources
install -p -m 0644 cmd/keymasterd/customization_data/web_resources/customization.css %{buildroot}/%{_datarootdir}/keymasterd/customization_data/web_resources/customization.css
%pre
/usr/bin/getent passwd keymaster || useradd -d /var/lib/keymaster -s /bin/false -U -r  keymaster

%post
mkdir -p /etc/keymaster/
mkdir -p /var/lib/keymaster
chown keymaster /var/lib/keymaster
systemctl daemon-reload

%postun
/usr/sbin/userdel keymaster
systemctl daemon-reload

%files
#%doc
%{_sbindir}/keymasterd
%{_bindir}/keymaster
%{_bindir}/keymaster-unlocker
/usr/lib/systemd/system/keymaster.service
%{_datarootdir}/keymasterd/static_files/*
%config(noreplace) %{_datarootdir}/keymasterd/customization_data/web_resources/*
%config(noreplace) %{_datarootdir}/keymasterd/customization_data/templates/*
%changelog
