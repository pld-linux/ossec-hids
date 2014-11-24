# Notes
# agent - read local files (syslog, snort, etc) and forward
# server -  above + notifications + remote agents
# local - do everything server does, but not recieve messages
# TODO:
#  - review patches
#  - review paths (to catch RHEL -> PLD differences)
#  - rewrite init script (this one is not working)
#  - review logrotate
#  - review permissions



%define asl 1
%define _default_patch_fuzz 2

%define prg  ossec

Summary:	An Open Source Host-based Intrusion Detection System
Summary(pl.UTF-8):	Otwartoźródłowy system monitorująco-kontrolujący systemy zawierający wszelkie apekty HIDS
Name:		ossec-hids
Version:	2.5.1
Release:	0.2
License:	GPL v3
Group:		Applications/System
Source0:	http://www.ossec.net/files/%{name}-%{version}.tar.gz
# Source0-md5:	94a7cabbba009728510a7a3e290ab200
Source1:	%{name}-find-requires
Source2:	%{name}.init
Source3:	asl_rules.xml
Source4:	authpsa_rules.xml
Source5:	asl-shun.pl
Source6:	%{name}.logrotate
Source7:	zabbix-alert.sh
Source8:	ossec-configure
Patch2:		decoder-asl.patch
Patch3:		syslog_rules.patch
Patch4:		ossec-client-conf.patch
Patch5:		firewall-drop-update.patch
Patch6:		disable-psql.patch
Patch9:		ossec-client-init.patch
Patch10:	smtp_auth-decoder.patch
Patch11:	courier-imap-rules.patch
Patch12:	denyhosts-decoder.patch
Patch13:	%{name}-server-reload.patch
URL:		http://www.ossec.net/
BuildRequires:	apache-devel
BuildRequires:	coreutils
BuildRequires:	inotify-tools-devel
BuildRequires:	mysql-devel
BuildRequires:	openssl-devel
Requires(post):	fileutils
Requires(post,preun):	/sbin/chkconfig
Requires(postun):	/usr/sbin/groupdel
Requires(postun):	/usr/sbin/userdel
Requires(pre):	/bin/id
Requires(pre):	/usr/bin/getgid
Requires(pre):	/usr/sbin/groupadd
Requires(pre):	/usr/sbin/useradd
Requires:	/sbin/chkconfig
Requires:	inotify-tools
Provides:	ossec = %{version}-%{release}
BuildRoot:	%{tmpdir}/%{name}-%{version}-root-%(id -u -n)

ExclusiveOS:	linux

%description
OSSEC HIDS is an Open Source Host-based Intrusion Detection System. It
performs log analysis, integrity checking, root kit detection,
time-based alerting and active response.

%description -l pl.UTF-8
OSSEC jest platformą monitorującą i kontrolującą systemy, zawierającą 
wszystkie aspekty HIDS (host-based intrusion detection), systemu 
monitorującego logi oraz SIM/SIEM (Security Informaton and Event 
Manager) w jednym rozwiązaniu. 

%package client
Summary:	The OSSEC HIDS Client
Group:		Applications/System
Requires:	%{name} = %{version}-%{release}
Provides:	ossec-client = %{version}-%{release}
Conflicts:	%{name}-server
%if %{asl}
Requires:	perl-DBD-SQLite
%endif

%package server
Summary:	The OSSEC HIDS Server
Group:		Applications/System
Requires:	%{name} = %{version}-%{release}
Provides:	ossec-server = %{version}-%{release}
Conflicts:	%{name}-client
%if %{asl}
Requires:	perl-DBD-SQLite
%endif


%description client
The %{name}-client package contains the client part of the OSSEC HIDS.
Install this package on every client to be monitored.

%description client -l pl.UTF-8
Paczka %{name}-client zawiera wszelkie elementy niezbędne do pracy
jako klient systemu OSSEC HIDS.

%description server
The %{name}-server package contains the server part of the OSSEC HIDS.
Install this package on a central machine for log collection and
alerting.

%description server -l pl.UTF-8
Paczka %{name}-server zawiera elementy niezbędne do uruchomienia 
centralnego serwera monitorującego i zbierającego alerty i logi z 
serwerów zdalnych (klientów).

%prep
%setup -q
%if %{asl}
%patch2 -p0
%patch3 -p0
%patch4 -p0
%patch5 -p0
%patch6 -p0
%patch10 -p1
%patch11 -p1
%patch12 -p1
%patch13 -p1
%endif
%patch9 -p0

# Prepare for docs
rm -rf contrib/specs
#find doc -type f -exec chmod 644 {} \;
#find contrib -type f -exec chmod 644 {} \;
#chmod 644 CONFIG INSTALL README BUGS
OLDPWD=`pwd`
cd doc/br
for i in `ls`
do
   iconv -f iso8859-1 -t utf-8 $i > $i.conv && mv -f $i.conv $i
done
cd $OLDPWD


%build
cd src
# Build the agent version first
echo "CEXTRA=-DCLIENT" >> ./Config.OS
%{__make} all
%{__make} build
mv addagent/manage_agents ../bin/manage_client
mv logcollector/ossec-logcollector  ../bin/client-logcollector
mv syscheckd/ossec-syscheckd  ../bin/client-syscheckd
# Rebuild for server
%{__make} clean
%{__make} setdb
%{__make} all
%{__make} build
#popd


# Generate the ossec-init.conf template
echo "DIRECTORY=\"%{_localstatedir}/%{prg}\"" >  %{prg}-init.conf
echo "VERSION=\"%{version}\""				 >> %{prg}-init.conf
echo "DATE=\"`date`\""						>> %{prg}-init.conf



%install
rm -rf $RPM_BUILD_ROOT
[ -n "${RPM_BUILD_ROOT}" -a "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}
install -d ${RPM_BUILD_ROOT}%{_initrddir}
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/{bin,stats,rules,tmp}
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/rules/translated/pure_ftpd
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/logs/{archives,alerts,firewall}
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/queue/{alerts,%{prg},fts,syscheck,rootcheck,agent-info,rids}
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/var/run
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/shared
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/templates
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/mysql
install -d ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/active-response/bin
strip -s -v bin/*

install src/%{prg}-init.conf ${RPM_BUILD_ROOT}%{_sysconfdir}
install etc/%{prg}.conf ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf.sample
install etc/%{prg}-{agent,server}.conf ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}
install etc/*.xml ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}
install etc/internal_options* ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}
install etc/rules/*xml ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/rules
install etc/rules/translated/pure_ftpd/* ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/rules/translated/pure_ftpd
install etc/templates/config/* ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/templates/
install bin/* ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/bin
install active-response/*.sh ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/active-response/bin
install src/rootcheck/db/*.txt ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/shared
install src/os_dbd/mysql.schema ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/mysql/mysql.schema
install src/init/%{prg}-{client,server}.sh ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/bin
install %{SOURCE2} ${RPM_BUILD_ROOT}%{_initrddir}/%{name}

touch ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf

%if %{asl}
install -d $RPM_BUILD_ROOT/etc/logrotate.d
install %{SOURCE3} ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/rules
install %{SOURCE4} ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/rules
install %{SOURCE5} ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/active-response/bin/asl-shun.pl
install %{SOURCE6} ${RPM_BUILD_ROOT}/etc/logrotate.d/ossec-hids
install %{SOURCE7} ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/active-response/bin/zabbix-alert.sh
install %{SOURCE8} ${RPM_BUILD_ROOT}%{_localstatedir}/%{prg}/bin/ossec-configure
%endif

%pre
if ! id -g %{prg} > /dev/null 2>&1; then
  groupadd -g 265 -r %{prg}
fi
if ! id -u %{prg} > /dev/null 2>&1; then
  useradd -u 265 -g %{prg} -G %{prg}       \
        -d %{_localstatedir}/%{prg} \
        -r -s /sbin/nologin %{prg} \
	-c "OSSec HIDS Monitor"
fi

%pre server
if ! id -u %{prg}m > /dev/null 2>&1; then
  useradd -u 266 -g %{prg} -G %{prg}       \
        -d %{_localstatedir}/%{prg} \
        -r -s /sbin/nologin %{prg}m \
	-c "OSSec HIDS Mail"
fi
if ! id -u %{prg}e > /dev/null 2>&1; then
  useradd -u 267 -g %{prg} -G %{prg}       \
        -d %{_localstatedir}/%{prg} \
        -r -s /sbin/nologin %{prg}e \
	-c "OSSec HIDS Daemon"
fi
if ! id -u %{prg}r > /dev/null 2>&1; then
  useradd -u 268 -g %{prg} -G %{prg}       \
        -d %{_localstatedir}/%{prg} \
        -r -s /sbin/nologin %{prg}r \
	-c "OSSec HIDS Remote Daemon"
fi


%post client
if [ $1 = 1 ]; then
  chkconfig --add %{name}
  chkconfig %{name} off
fi

echo "TYPE=\"agent\"" >> %{_sysconfdir}/%{prg}-init.conf
chmod 600 %{_sysconfdir}/%{prg}-init.conf

if [ ! -f %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf ]; then
ln -sf %{prg}-agent.conf %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf
fi

ln -sf %{prg}-client.sh %{_localstatedir}/%{prg}/bin/%{prg}-control

# daemon trickery
ln -sf /var/ossec/bin/ossec-client-logcollector /var/ossec/bin/ossec-logcollector
ln -sf /var/ossec/bin/ossec-client-syscheckd    /var/ossec/bin/ossec-syscheckd
ln -sf %{_localstatedir}/%{prg}/bin/client-logcollector  %{_localstatedir}/%{prg}/bin/%{prg}-logcollector
ln -sf %{_localstatedir}/%{prg}/bin/client-syscheckd  %{_localstatedir}/%{prg}/bin/%{prg}-syscheckd
chmod -R 550 %{_localstatedir}/%{prg}/bin/


touch %{_localstatedir}/%{prg}/logs/ossec.log
chown %{prg}:%{prg} %{_localstatedir}/%{prg}/logs/ossec.log
chmod 0664 %{_localstatedir}/%{prg}/logs/ossec.log

if [ -f %{_localstatedir}/lock/subsys/%{name} ]; then
  %{_initrddir}/%{name} restart
fi

%post server
if [ $1 = 1 ]; then
  chkconfig --add %{name}
  chkconfig %{name} off
fi

echo "TYPE=\"server\"" >> %{_sysconfdir}/%{prg}-init.conf
chmod 600 %{_sysconfdir}/%{prg}-init.conf

if [ ! -f %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf ]; then
ln -sf %{prg}-server.conf %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf
fi

ln -sf %{prg}-server.sh %{_localstatedir}/%{prg}/bin/%{prg}-control
chmod -R 550 %{_localstatedir}/%{prg}/bin/

touch %{_localstatedir}/%{prg}/logs/ossec.log
chown %{prg}:%{prg} %{_localstatedir}/%{prg}/logs/ossec.log
chmod 0664 %{_localstatedir}/%{prg}/logs/ossec.log

if [ -f %{_localstatedir}/lock/subsys/%{name} ]; then
  %{_initrddir}/%{name} restart
fi

chmod 550 /var/ossec/rules /var/ossec/tmp
chmod 700 /var/ossec/queue/rootcheck /var/ossec/queue/fts
chmod 750 /var/ossec/logs/alerts /var/ossec/logs/archives /var/ossec/stats /var/ossec/logs/firewall


%preun client
if [ $1 = 0 ]; then
  chkconfig %{name} off
  chkconfig --del %{name}

  if [ -f %{_localstatedir}/lock/subsys/%{name} ]; then
    %{_initrddir}/%{name} stop
  fi

rm -f %{_localstatedir}/%{prg}%{_sysconfdir}/localtime
rm -f %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf
  rm -f %{_localstatedir}/%{prg}/bin/%{prg}-control
  rm -f %{_localstatedir}/%{prg}/bin/%{prg}-logcollector
  rm -f %{_localstatedir}/%{prg}/bin/%{prg}-syscheckd
fi

%preun server
if [ $1 = 0 ]; then
  chkconfig %{name} off
  chkconfig --del %{name}

  if [ -f %{_localstatedir}/lock/subsys/%{name} ]; then
    %{_initrddir}/%{name} stop
  fi

rm -f %{_localstatedir}/%{prg}%{_sysconfdir}/localtime
rm -f %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}.conf
  rm -f %{_localstatedir}/%{prg}/bin/%{prg}-control
fi


%triggerin -- glibc
[ -r %{_sysconfdir}/localtime ] && cp -fpL %{_sysconfdir}/localtime %{_localstatedir}/%{prg}/etc


%clean
[ -n "${RPM_BUILD_ROOT}" -a "${RPM_BUILD_ROOT}" != "/" ] && rm -rf ${RPM_BUILD_ROOT}
chmod 644 %{SOURCE1}



%files
%defattr(644,root,root,755)
%doc BUGS CONFIG INSTALL* README
%doc %dir contrib doc
%attr(550,root,%{prg}) %dir %{_localstatedir}/%{prg}
%attr(550,root,%{prg}) %dir %{_localstatedir}/%{prg}/active-response
%attr(550,root,%{prg}) %dir %{_localstatedir}/%{prg}/active-response/bin
%attr(755,root,%{prg}) %dir %{_localstatedir}/%{prg}/bin
%attr(550,root,%{prg}) %dir %{_localstatedir}/%{prg}%{_sysconfdir}
%attr(770,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}%{_sysconfdir}/shared
%attr(750,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}%{_sysconfdir}/templates
%attr(640,%{prg},%{prg}) %{_localstatedir}/%{prg}%{_sysconfdir}/templates/*
%attr(750,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/logs
%attr(550,root,%{prg}) %dir %{_localstatedir}/%{prg}/queue
%attr(770,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/queue/alerts
%attr(770,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/queue/%{prg}
%attr(750,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/queue/syscheck
%attr(550,root,%{prg}) %dir %{_localstatedir}/%{prg}/var
%attr(770,root,%{prg}) %dir %{_localstatedir}/%{prg}/var/run
%if %{asl}
%config(noreplace) /etc/logrotate.d/ossec-hids
%{_localstatedir}/%{prg}/bin/%{prg}-configure
%endif


%files client
%defattr(644,root,root,755)
%doc BUGS CONFIG  INSTALL* README
%doc %dir contrib doc
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{prg}-init.conf
%{_initrddir}/*
%config(noreplace) %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}-agent.conf
%config(noreplace) %{_localstatedir}/%{prg}%{_sysconfdir}/internal_options*
%config(noreplace) %{_localstatedir}/%{prg}%{_sysconfdir}/shared/*
%{_localstatedir}/%{prg}%{_sysconfdir}/*.sample
%{_localstatedir}/%{prg}/active-response/bin/*
%{_localstatedir}/%{prg}/bin/%{prg}-client.sh
%{_localstatedir}/%{prg}/bin/%{prg}-agentd
%{_localstatedir}/%{prg}/bin/client-logcollector
%{_localstatedir}/%{prg}/bin/client-syscheckd
%{_localstatedir}/%{prg}/bin/%{prg}-execd
%{_localstatedir}/%{prg}/bin/manage_client
%attr(755,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/queue/rids

%files server
%defattr(644,root,root,755)
%doc BUGS CONFIG INSTALL* README
%doc %dir contrib doc
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/%{prg}-init.conf
%{_initrddir}/*
%ghost %config(missingok,noreplace) %{_localstatedir}/%{prg}%{_sysconfdir}/ossec.conf
%config(noreplace) %{_localstatedir}/%{prg}%{_sysconfdir}/%{prg}-server.conf
%config(noreplace) %{_localstatedir}/%{prg}%{_sysconfdir}/internal_options*
%config %{_localstatedir}/%{prg}%{_sysconfdir}/*.xml
%config(noreplace) %{_localstatedir}/%{prg}%{_sysconfdir}/shared/*
%{_localstatedir}/%{prg}%{_sysconfdir}/mysql/mysql.schema
%{_localstatedir}/%{prg}%{_sysconfdir}/*.sample
%{_localstatedir}/%{prg}/active-response/bin/*
%{_localstatedir}/%{prg}/bin/%{prg}-server.sh
%{_localstatedir}/%{prg}/bin/%{prg}-agentd
%{_localstatedir}/%{prg}/bin/%{prg}-analysisd
%{_localstatedir}/%{prg}/bin/%{prg}-execd
%{_localstatedir}/%{prg}/bin/%{prg}-logcollector
%{_localstatedir}/%{prg}/bin/%{prg}-makelists
%{_localstatedir}/%{prg}/bin/%{prg}-regex
%{_localstatedir}/%{prg}/bin/%{prg}-maild
%{_localstatedir}/%{prg}/bin/%{prg}-monitord
%{_localstatedir}/%{prg}/bin/%{prg}-remoted
%{_localstatedir}/%{prg}/bin/%{prg}-syscheckd
%{_localstatedir}/%{prg}/bin/%{prg}-dbd
%{_localstatedir}/%{prg}/bin/%{prg}-reportd
%{_localstatedir}/%{prg}/bin/%{prg}-agentlessd
%{_localstatedir}/%{prg}/bin/ossec-csyslogd
%{_localstatedir}/%{prg}/bin/list_agents
%{_localstatedir}/%{prg}/bin/manage_agents
%{_localstatedir}/%{prg}/bin/syscheck_update
%{_localstatedir}/%{prg}/bin/clear_stats
%{_localstatedir}/%{prg}/bin/agent_control
%{_localstatedir}/%{prg}/bin/rootcheck_control
%{_localstatedir}/%{prg}/bin/syscheck_control
%{_localstatedir}/%{prg}/bin/ossec-logtest
%{_localstatedir}/%{prg}/bin/verify-agent-conf


%attr(755,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/logs/archives
%attr(755,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/logs/alerts
%attr(755,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/logs/firewall
%attr(755,%{prg}r,%{prg}) %dir %{_localstatedir}/%{prg}/queue/agent-info
%attr(755,%{prg}r,%{prg}) %dir %{_localstatedir}/%{prg}/queue/rids
%attr(755,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/queue/fts
%attr(755,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/queue/rootcheck
%attr(755,root,%{prg}) %dir %{_localstatedir}/%{prg}/rules
%config(noreplace) %{_localstatedir}/%{prg}/rules/*
%attr(755,%{prg},%{prg}) %dir %{_localstatedir}/%{prg}/stats
%attr(755,root,%{prg}) %dir %{_localstatedir}/%{prg}/tmp
