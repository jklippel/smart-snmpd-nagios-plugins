## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include $(PTHREAD_CFLAGS) @CLIBFLAGS@
LDADD = @LINKFLAGS@

bin_PROGRAMS=	check_fs_by_snmp \
		check_cpu_by_snmp \
		check_procs_by_snmp \
		check_mem_by_snmp \
		check_swap_by_snmp \
		check_load_by_snmp \
		check_user_cnt_by_snmp \
		check_proc_cnt_by_snmp \
                check_snmp_daemon_avail \
                check_snmp_agent_avail

check_fs_by_snmp_SOURCES=	check_fs_by_snmp.cpp

check_cpu_by_snmp_SOURCES=	check_cpu_by_snmp.cpp

check_procs_by_snmp_SOURCES=	check_procs_by_snmp.cpp

check_mem_by_snmp_SOURCES=	check_mem_by_snmp.cpp

check_swap_by_snmp_SOURCES=	check_swap_by_snmp.cpp

check_load_by_snmp_SOURCES=	check_load_by_snmp.cpp

check_user_cnt_by_snmp_SOURCES=	check_user_cnt_by_snmp.cpp

check_proc_cnt_by_snmp_SOURCES=	check_proc_cnt_by_snmp.cpp

check_snmp_daemon_avail_SOURCES=check_snmp_daemon_avail.cpp

check_snmp_agent_avail_SOURCES=	check_snmp_agent_avail.cpp

EXTRA_DIST = test_plugin.sh

netsnmpcompattest:
	./test_plugin.sh 0 ./check_cpu_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C
	./test_plugin.sh 3 ./check_cpu_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -s smart-snmpd
	./test_plugin.sh 0 ./check_cpu_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -s net-snmpd
	./test_plugin.sh 255 ./check_cpu_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -s foo
	./test_plugin.sh 0 ./check_fs_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -n / -w 80% -c 90% -s net-snmpd
	./test_plugin.sh 0 ./check_mem_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C
	./test_plugin.sh 0 ./check_swap_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C
	./test_plugin.sh 0 ./check_user_cnt_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -w 10 -c 20
	./test_plugin.sh 0 ./check_proc_cnt_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C
	./test_plugin.sh 0 ./check_snmp_daemon_avail -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C
	./test_plugin.sh 2 ./check_snmp_daemon_avail -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -s smart-snmpd
	./test_plugin.sh 0 ./check_snmp_agent_avail -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C
	./test_plugin.sh 0 ./check_snmp_agent_avail -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -w 25m,150,150 -c 55m,300,300
	./test_plugin.sh 0 ./check_load_by_snmp -H $(NETSNMPDIP) -p $(NETSNMPDPORT) -C $(NETSNMPCOMM) -V 2C -w 40,80,160 -c 80,160,320

test: $(bin_PROGRAMS)
	./test_plugin.sh 0 ./check_cpu_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C
	./test_plugin.sh 0 ./check_cpu_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C -s smart-snmpd
	./test_plugin.sh 3 ./check_cpu_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C -s net-snmpd
	./test_plugin.sh 255 ./check_cpu_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C -s foo
	./test_plugin.sh 0 ./check_fs_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C -n / -w 80%,2G -c 90%,1G
	./test_plugin.sh 0 ./check_mem_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C
	./test_plugin.sh 0 ./check_swap_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C
	./test_plugin.sh 0 ./check_user_cnt_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C -w 30 -c 200
	./test_plugin.sh 0 ./check_proc_cnt_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C
	./test_plugin.sh 0 ./check_snmp_daemon_avail -H 127.0.0.1 -p 8161 -C public -V 2C
	./test_plugin.sh 0 ./check_snmp_agent_avail -H 127.0.0.1 -p 8161 -C public -V 2C
	./test_plugin.sh 0 ./check_snmp_agent_avail -H 127.0.0.1 -p 8161 -C public -V 2C
	./test_plugin.sh 0 ./check_snmp_agent_avail -H 127.0.0.1 -p 8161 -C public -V 2C -w 25m,150,150 -c 55m,300,300
	./test_plugin.sh 0 ./check_load_by_snmp -H 127.0.0.1 -p 8161 -C public -V 2C -w 5,10 -c 10,20
