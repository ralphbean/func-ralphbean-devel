
%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Summary: Remote config, monitoring, and management api
Name: func
Source1: version
Version: %(echo `awk '{ print $1 }' %{SOURCE1}`)
Release: %(echo `awk '{ print $2 }' %{SOURCE1}`)%{?dist}
Source0: %{name}-%{version}.tar.gz
License: GPL+
Group: Applications/System
Requires: python >= 2.3
Requires: rhpl
Requires: yum-utils
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildArch: noarch
Url: https://hosted.fedoraproject.org/projects/func/

%description

func is a remote api for mangement, configation, and monitoring of systems.

%prep
%setup -q

%build
%{__python} setup.py build

%install
test "x$RPM_BUILD_ROOT" != "x" && rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install --root=$RPM_BUILD_ROOT

%clean
rm -fr $RPM_BUILD_ROOT

%files
%{_bindir}/funcd
%{_bindir}/func
%{_bindir}/certmaster
/etc/init.d/funcd
/etc/init.d/certmaster
%config(noreplace) /etc/func/settings
%config(noreplace) /etc/func/certmaster.conf
%dir %{python_sitelib}/func
%dir %{python_sitelib}/func/minion
%dir %{python_sitelib}/func/overlord
%{python_sitelib}/func/minion/*.py*
%{python_sitelib}/func/overlord/*.py*
%{python_sitelib}/func/*.py*
%dir %{python_sitelib}/func/minion/modules
%{python_sitelib}/func/minion/modules/*.py*
%dir /var/log/func

%post
/sbin/chkconfig --add funcd
exit 0

%preun
if [ "$1" = 0 ] ; then
  /sbin/service funcd stop > /dev/null 2>&1
  /sbin/chkconfig --del funcd
fi


%changelog
* Tue Sep 25 2007 Robin Norwood <rnorwood@redhat.com> - 0.0.11-3
- Change server -> minion and client -> overlord

* Thu Sep 20 2007 James Bowes <jbowes@redhat.com> - 0.0.11-2
- Clean up some speclint warnings

* Thu Sep 20 2007 Adrian Likins <alikins@redhat.com> - 0.0.11-1
- initial release (this one goes to .11)
