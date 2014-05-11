#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# don't require higher autoconf version for win32 support
AC_PREREQ([2.63])
AC_INIT([smart-snmpd-nagios-plugins], [0.2.0], [noreply@smart-snmpd.org], [smart-snmpd-nagios-plugins])
SSNC_MAJOR_VERSION=0
SSNC_MINOR_VERSION=2
SSNC_MICRO_VERSION=0
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([src/check_fs_by_snmp.cpp])
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE([disable])

dnl
dnl Get cannonical host
dnl
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([OS_TYPE], "$host_os",
                   [Define to be the name of the operating system.])

dnl disable unnecessary compiler checks
AC_DEFUN([AC_PROG_F77], [:])
AC_DEFUN([AC_PROG_FC], [:])
AC_DEFUN([AC_PROG_OBJC], [:])
AC_DEFUN([AC_PROG_OBJCCPP], [:])
AC_DEFUN([AC_LIBTOOL_F77], [:])

dnl disable check for GNU compatible malloc - just a working malloc is enough
AC_DEFUN([AC_FUNC_MALLOC_IF], [:])
AC_DEFUN([AC_FUNC_MALLOC], [
  AC_CHECK_FUNCS([malloc realloc])
])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_GREP
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

# Check for extra flags to enable some kind of behavior
AC_CHECK_DECL([_AIX],[ac_cv_need_minus_d_linux_source_compat="yes"; ac_cv_need_minus_d_all_source="yes"])
AC_CHECK_DECL([__linux],[ac_cv_need_minus_d_gnu_source="yes"]) dnl probably required by kfreebsd, too?
AC_CHECK_DECL([__sun],[ac_cv_need_minus_d_extensions="yes"])

AS_IF([test "x$ac_cv_need_minus_d_linux_source_compat" = "xyes"],
      [CPPFLAGS="$CPPFLAGS -D_LINUX_SOURCE_COMPAT"])

AS_IF([test "x$ac_cv_need_minus_d_gnu_source" = "xyes"],
      [CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"])

AS_IF([test "x$ac_cv_need_minus_d_all_source" = "xyes"],
      [CPPFLAGS="$CPPFLAGS -D_ALL_SOURCE"])

AS_IF([test "x$ac_cv_need_minus_d_extensions" = "xyes"],
      [CPPFLAGS="$CPPFLAGS -D__EXTENSIONS__"])

ACX_CHECK_XOPEN_SOURCE
AS_IF([test -n "$XOPEN_SOURCE_CPPFLAGS"], [CPPFLAGS="$CPPFLAGS $XOPEN_SOURCE_CPPFLAGS"])

dnl
dnl Process features.
dnl
ACX_CHECK_WITH_LIB([snmp++],[yes])
ACX_CHECK_WITH_LIB([log4cplus],[yes])
ACX_CHECK_WITH_LIB([boost],[yes])

AC_ARG_ENABLE(debug,
[  --disable-debug         disable support for debugging output],
ENABLE_DEBUG=$enableval, ENABLE_DEBUG=yes)
AC_ARG_ENABLE(namespace,
[  --enable-namespace      enable using of namespace (default: on if supported)
  --disable-namespace     disable using of namespace],
ENABLE_NAMESPACE=$enableval, ENABLE_NAMESPACE=check)

AS_IF([test "x${ENABLE_DEBUG}" = "xyes"],
      [AC_DEFINE([DEBUG], 1, [Define if you want the debug output support compiled in.])],
      [AC_LIB_APPENDTOVAR([CXXFLAGS], [-D_NDEBUG])]
)

# Checks for optional dependencies
ACX_WIN32(
[],
[
    AX_PTHREAD([
        AC_DEFINE(HAVE_PTHREAD, 1,
            [Define if you have POSIX threads libraries and header files.])
        CC="$PTHREAD_CC"
        CXX="$PTHREAD_CXX"
        AS_IF([test -n "$PTHREAD_LIBS"], [LIBS="$PTHREAD_LIBS $LIBS"])
        AS_IF([test -n "$PTHREAD_CFLAGS"], [
          CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
          CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
        ])
        ac_cv_enable_threads=yes
        
        dnl Checks for nanosleep library:
        AC_SEARCH_LIBS(nanosleep, [rt])
    ],
    [])
])

LINKFLAGS=""
CLIBFLAGS=""

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h ctype.h errno.h fcntl.h float.h limits.h memory.h netdb.h netinet/in.h poll.h pwd.h signal.h stdarg.h stdio.h stdlib.h string.h strings.h sys/fcntl.h sys/file.h sys/param.h sys/select.h sys/socket.h sys/time.h sys/timeb.h sys/types.h sys/unistd.h sys/wait.h time.h unistd.h])

ACX_WIN32(
    AC_CHECK_HEADERS([io.h process.h winsock.h winsock2.h wstcpip.h wspiapi.h])
    AC_CHECK_LIB([wsock32],[main])
    AC_CHECK_LIB([ws2_32],[main]),
    []
)

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_UID_T
AC_CXX_BOOL

ACX_CHECK_VISIBILITY(
[
	SSNC_EXPORT="$acx_visibility_export"
	SSNC_IMPORT="$acx_visibility_import"
	SSNC_PRIVATE="$acx_visibility_private"
	WITH_VISIBILITY_SUPPORT=1
	AC_SUBST(SSNC_EXPORT)
	AC_SUBST(SSNC_IMPORT)
	AC_SUBST(SSNC_PRIVATE)
],[
	WITH_VISIBILITY_SUPPORT=0
])
AC_SUBST(WITH_VISIBILITY_SUPPORT)

# Checks for libraries.
AS_IF([test "x${acx_with_libsnmp}" != "xyes"], [AC_MSG_ERROR([libsnmp++ is mandatory and must not be disabled])])
AS_IF([test "x${acx_with_libboost}" != "xyes"], [AC_MSG_ERROR([boost is mandatory and must not be disabled])])
AC_LANG_PUSH([C++])

dnl pull the rabbit out of the hat to avoid regexp in ACX_CHECK_LIB_FLAGS searching for winsock2.h
acx_include_sockets="\
#if HAVE_WINSOCK2_H
# include <winsock2.h>
# if HAVE_WS2TCPIP_H
#  include <ws2tcpip.h>
# endif
# if HAVE_WSPIAPI_H
#  include <wspiapi.h>
# endif
#elif HAVE_WINSOCK_H
  /* IIRC winsock.h must be included before windows.h */
# include <winsock.h>
#else
# ifdef HAVE_NETDB_H
#  include <netdb.h>
# endif
# ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# endif
# ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
# endif
# ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif
#endif"

ACX_CHECK_LIB_FLAGS([snmp++], [], [
#ifdef SNMP_PP_NAMESPACE
Snmp_pp::
#endif
DefaultLog::log ()
  ], [
AC_INCLUDES_DEFAULT
$acx_include_sockets

#include <snmp_pp/snmp_pp.h>
  ], [snmp++-3 >= 3.2.25], [
    WITH_LIBSNMP=1
    AC_LIB_APPENDTOVAR([LINKFLAGS], ${LIBS_SNMP})
    AC_LIB_APPENDTOVAR([CLIBFLAGS], ${INC_SNMP})
    AC_MSG_NOTICE([compiling in support for libsnmp++ (LIBS="$LIBS_SNMP")])
  ]
)
AC_MSG_CHECKING([if libsnmp++ is built with SNMPv3 support])
acx_cppflags_safe="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $CLIBFLAGS"
AC_COMPILE_IFELSE([
AC_INCLUDES_DEFAULT
$acx_include_sockets

#include <snmp_pp/config_snmp_pp.h>
#if !defined(_SNMPv3)
#error ProxyForwarder requires SNMPv3
#endif

int main() { return 0; }
  ], [
    AC_MSG_RESULT([yes])
    acx_libsnmp_snmpv3=yes
  ], [
    AC_MSG_RESULT([no])
    acx_libsnmp_snmpv3=no
  ]
)

AC_MSG_CHECKING([if libsnmp++ is built with logging support])
AC_COMPILE_IFELSE([
AC_INCLUDES_DEFAULT
$acx_include_sockets

#include <snmp_pp/config_snmp_pp.h>
#if defined(_NO_LOGGING)
#error no logging
#endif

int main() { return 0; }
  ], [
    AC_MSG_RESULT([yes])
    acx_libsnmp_logging=yes
  ], [
    AC_MSG_RESULT([no])
    acx_libsnmp_logging=no
  ]
)
CPPFLAGS="$acx_cppflags_safe"

AM_CONDITIONAL(WITH_LIBLOG4CPLUS,false)
SSNC_WITH_LIBLOG4CPLUS=0
AS_IF([test "x$acx_libsnmp_logging" = "xyes"], [
  AS_IF([test "x${acx_with_liblog4cplus}" != "xyes"], [AC_MSG_ERROR([log4cplus is mandatory and must not be disabled])])

  AS_IF([test "x$acx_libsnmp_logging" = "xyes"], [
    ACX_CHECK_LIB_FLAGS([log4cplus], [], [log4cplus::BasicConfigurator config; config.configure()], [
#include <log4cplus/logger.h>
#include <log4cplus/configurator.h>
      ], [log4cplus >= 1.0.5], [
        AC_LIB_APPENDTOVAR([LINKFLAGS], ${LIBS_LOG4CPLUS})
        AC_LIB_APPENDTOVAR([CLIBFLAGS], ${INC_LOG4CPLUS})
        AM_CONDITIONAL(WITH_LIBLOG4CPLUS,true)
        SSNC_WITH_LIBLOG4CPLUS=1
        AC_MSG_NOTICE([compiling in support for liblog4cplus (LIBS="$LIBS_LOG4CPLUS")])

        AC_MSG_CHECKING([if liblog4cplus is built with thread support])
        acx_cppflags_safe="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS $CLIBFLAGS"
        AC_COMPILE_IFELSE([
        AC_INCLUDES_DEFAULT

#include <log4cplus/config.hxx>
#if defined(LOG4CPLUS_SINGLE_THREADED)
#error no threads
#endif

        int main() { return 0; }
          ], [
            AC_MSG_RESULT([yes])
            acx_liblog4cplus_threads=yes
          ], [
            AC_MSG_RESULT([no])
            acx_liblog4cplus_threads=no
          ]
        )
        CPPFLAGS="$acx_cppflags_safe"
      ]
    )
  ])
])

ACX_CHECK_LIB_FLAGS([boost,boost_program_options boost_regex], [], [
boost::program_options::options_description desc("Allowed options");
boost::regex re;
re.assign( ".*aaa.*[[0-9]]+", boost::regex_constants::icase );
  ], [
AC_INCLUDES_DEFAULT

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/regex.hpp>
  ], , [
    WITH_LIBBOOST=1
    AC_LIB_APPENDTOVAR([LINKFLAGS], ${LIBS_BOOST})
    AC_LIB_APPENDTOVAR([CLIBFLAGS], ${INC_BOOST})
    AC_MSG_NOTICE([compiling in support for boost (LIBS="$LIBS_BOOST")])
  ]
)

AC_LANG_POP([C++])

AC_CHECK_TYPES([struct sockaddr_in6],,,[
AC_INCLUDES_DEFAULT
$acx_include_sockets
])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_ALLOCA
AC_CHECK_FUNCS([strerror])

AX_CXX_NAMESPACES
AX_CXX_NAMESPACE_STD
AX_CXX_HAVE_STL
AX_CXX_HAVE_STD
AX_CXX_TEMPLATES
AX_CXX_HEADER_STDCXX_98
AX_CXX_HEADER_STDCXX_TR1
AX_CXX_HEADER_STDCXX_0X

AS_IF(
  [test "x${ENABLE_NAMESPACE}" = "xyes"],
  [
    AS_IF([test "x$ax_cv_cxx_namespaces" = "xyes"],
          [
            WITH_NAMESPACE=1
            AC_MSG_NOTICE([enable using of namespaces])
          ],
          [AC_MSG_FAILURE([C++ compiler does not support namespaces])])
  ],
  [test "x${ENABLE_NAMESPACE}" = "xcheck"],
  [
    AS_IF([test "x$ax_cv_cxx_namespaces" = "xyes"],
          [
            WITH_NAMESPACE=1
            AC_MSG_NOTICE([enable using of namespaces])
          ],
          [
            WITH_NAMESPACE=0
            AC_MSG_NOTICE([disable using of namespaces])
          ])
  ],
  [
    WITH_NAMESPACE=0
    AC_MSG_NOTICE([disable using of namespaces])
  ]
)

AS_IF([test "x$SSNC_WITH_LIBLOG4CPLUS" = "x1"], [
        :
])

# Check if user wants to make tests
AC_ARG_ENABLE(tests,
[  --enable-tests          enable test building (default in maintainer-mode)
  --disable-tests         disable test building (default in all other cases)],
        [ENABLE_TESTS="${enableval}"],
        [
		AS_IF(	[test "x$USE_MAINTAINER_MODE" = "xyes"],
			[ENABLE_TESTS="yes"],
			[ENABLE_TESTS="check"]
		)
        ]
)

AM_CONDITIONAL(TESTS, false)
AM_CONDITIONAL(TEST_SCRIPTS, false)
AS_IF(	[test "x$ENABLE_TESTS" != "xno"],
	[
		AM_CONDITIONAL(TESTS, true)
		ACX_PROG_PERL5( , , [5.006], [Getopt::Long, Test::More 0.90, Data::Dumper], [
				AC_MSG_NOTICE([enabling build of test automation using $PERL5])
				AM_CONDITIONAL(TEST_SCRIPTS, true)
			], [
				AS_IF(	[test "x$ENABLE_TESTS" = "xyes"], [
					AC_MSG_FAILURE([Tests are required but no suitable Perl5 environment found])
				])
			]
		)
        ]
)

AM_CONDITIONAL(CFG_DIR, false)
AC_ARG_WITH([cfg-dir],
[  --with-cfg-dir=/path/to/csv   use given directory to look for additional
                                placeholders to fulfil the test configuration],
    [AS_IF([test -d "${withval}"], [
        CFG_DIR="${withval}"
        AC_SUBST(CFG_DIR)
        AM_CONDITIONAL(CFG_DIR, true)
    ], [AC_MSG_ERROR([File ${withval} does not exists])])]
)

dnl Libtool setup.
dnl must be latest to catch rpath compiled in by changes made during checks before

LT_INIT
AC_PROG_LIBTOOL

dnl finish
AC_SUBST(SSNC_MAJOR_VERSION)
AC_SUBST(SSNC_MINOR_VERSION)
AC_SUBST(SSNC_MICRO_VERSION)

AC_SUBST(LINKFLAGS)
AC_SUBST(CLIBFLAGS)

AC_SUBST(SSNC_WITH_NAMESPACE)
AC_SUBST(SSNC_WITH_LIBLOG4CPLUS)

AC_SUBST(NEED_DEFINE_BOOL)

AC_CONFIG_FILES([Makefile include/Makefile include/smart-snmpd-nagios-plugins/Makefile src/Makefile tests/Makefile tests/testlib/Makefile tests/local_tests/Makefile tests/remote_tests/Makefile tests/smooth_tests/Makefile tests/snmpd_tests/Makefile])
AC_OUTPUT(include/smart-snmpd-nagios-plugins/smart-snmpd-nagios-plugins.h)
