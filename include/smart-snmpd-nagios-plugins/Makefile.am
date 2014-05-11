## Process this file with automake to produce Makefile.in

if WITH_LIBLOG4CPLUS
log4cplus_headers =	log4cplus.h
endif

noinst_HEADERS =	oids.h \
			nagios-stats.h \
			program-options.h \
			std-ext.h \
			snmp-pp-std.h \
			snmp-comm.h \
			snmp-comm-types.h \
			snmp-check.h \
			snmp-check-types.h \
			snmp-appl.h \
			snmp-check-appl.h \
			snmp-daemon-identifiers.h \
			smart-snmpd-nagios-plugins.h \
			$(log4cplus_headers)

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(smartsnmpdincdir)

EXTRA_DIST = smart-snmpd-nagios-plugins.h.in
