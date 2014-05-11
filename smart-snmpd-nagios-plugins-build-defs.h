/**
 * Copyright 2010 Matthias Haag, Jens Rehsack
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __BUILD_SMART_SNMPD_H_INCLUDED__
#define __BUILD_SMART_SNMPD_H_INCLUDED__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#if defined(__cplusplus) && defined(STDCXX_98_HEADERS)
# include <cctype>
# include <cerrno>
# include <climits>
# include <csignal>
# include <cstdarg>
# include <cstddef>
# include <cstdio>
# include <cstdlib>
# include <cstring>
# include <ctime>
#else
# include <stdio.h>
# ifdef STDC_HEADERS
#  include <stdlib.h>
#  include <stddef.h>
#  include <stdarg.h>
# else
#  ifdef HAVE_STDLIB_H
#   include <stdlib.h>
#  endif
#  ifdef HAVE_STDARG_H
#   include <stdarg.h>
#  endif
# endif
# ifdef HAVE_STRING_H
#  if !defined STDC_HEADERS && defined HAVE_MEMORY_H
#   include <memory.h>
#  endif
#  include <string.h>
# endif
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
# ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
# endif
# ifdef HAVE_CTYPE_H
#  include <ctype.h>
# endif
# ifdef HAVE_SIGNAL_H
#  include <signal.h>
# endif
# ifdef HAVE_ERRNO_H
#  include <errno.h>
# endif
# ifdef HAVE_TIME_H
#  include <time.h>
# endif
#endif

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#elif defined __GNUC__
# define alloca __builtin_alloca
#elif defined _AIX
# define alloca __alloca
#elif defined _MSC_VER
# include <malloc.h>
# define alloca _alloca
#else
# ifndef HAVE_ALLOCA
#  ifdef  __cplusplus
extern "C"
#  endif
void *alloca (size_t);
# endif
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#elif defined(HAVE_SYS_UNISTD_H)
# include <sys/unistd.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TIMEB_H
#include <sys/timeb.h> // and _ftime
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
# include <sys/fcntl.h>
#endif
#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

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
#endif

#ifdef HAVE_POLL_H
# include <poll.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifdef _WIN32
# ifdef HAVE_IO_H
#  include <io.h>
# endif
# ifdef HAVE_PROCESS_H
#  include <process.h>
# endif
# include <windows.h>
#endif

#ifndef HAVE_STRCASECMP
# ifdef HAVE_STRICMP
#  define strcasecmp stricmp
# else
int strcasecmp(const char *s1, const char *s2);
# endif
#endif

#ifndef HAVE_FLOCK
# if defined(HAVE_FCNTL) && defined(HAVE_DECL_F_SETLK)
int flock(int fd, int op);
# ifndef LOCK_SH
#  define LOCK_SH 1
# endif
# ifndef LOCK_EX
#  define LOCK_EX 2
# endif
# ifndef LOCK_UN
#  define LOCK_UN 3
# endif
# ifndef LOCK_NB
#  define LOCK_NB 8
# endif
# endif
#endif

#ifndef HAVE_GETPID
# ifdef HAVE__GETPID
#  define getpid _getpid
# endif
#endif

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY
# ifdef HAVE_STRUCT_SOCKADDR_STORAGE___SS_FAMILY
#  define ss_family __ss_family
# endif
#endif

/* Minimum of signed integral types.  */
#ifndef INT8_MIN
# define INT8_MIN               (-128)
#endif
#ifndef INT16_MIN
# define INT16_MIN              (-32767-1)
#endif
#ifndef INT32_MIN
# define INT32_MIN              (-2147483647-1)
#endif
#ifndef INT64_MIN
# define INT64_MIN              (-int64_t(9223372036854775807)-1)
#endif
/* Maximum of signed integral types.  */
#ifndef INT_MAX
# define INT8_MAX               (127)
#endif
#ifndef INT16_MAX
# define INT16_MAX              (32767)
#endif
#ifndef INT32_MAX
# define INT32_MAX              (2147483647)
#endif
#ifndef INT64_MAX
# define INT64_MAX              (int64_t(9223372036854775807))
#endif

/* Maximum of unsigned integral types.  */
#ifndef UINT8_MAX
# define UINT8_MAX              (255)
#endif
#ifndef UINT16_MAX
# define UINT16_MAX             (65535)
#endif
#ifndef UINT32_MAX
# define UINT32_MAX             (4294967295U)
#endif
#ifndef UINT64_MAX
# define UINT64_MAX             (uint64_t(18446744073709551615))
#endif

#ifndef NULL
#define NULL	0
#endif

#ifdef __cplusplus
# ifdef STDCXX_98_HEADERS
#  include <iostream>
# else
#  include <iostream.h>
# endif

# include <snmp_pp/config_snmp_pp.h>
# include <snmp_pp/log.h>

# ifdef _THREADS
#  ifndef _WIN32THREADS
#   include <pthread.h>
#  endif
# endif

# ifdef HAVE_NAMESPACE_STD
using namespace std;
# endif

# ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#  ifndef NS_SNMP
#   define NS_SNMP Snmp_pp::
#  endif
# endif

#endif /* __cplusplus */

#define lengthof(x) (sizeof(x)/sizeof((x)[0]))

#endif /* ?__BUILD_SMART_SNMPD_H_INCLUDED__ */
