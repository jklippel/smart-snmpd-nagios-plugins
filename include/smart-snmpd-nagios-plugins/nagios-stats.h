/*
 * Copyright 2010,2011 Matthias Haag, Jens Rehsack
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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_NAGIOS_STATS_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_NAGIOS_STATS_H_INCLUDED__

/*
 * Exit codes
 */
#define STATE_OK		0
#define STATE_WARNING		1
#define STATE_CRITICAL		2
#define STATE_UNKNOWN		3
#define STATE_DEPENDENT		4
#define STATE_VALID_MAX		STATE_DEPENDENT
#define STATE_EXCEPTION		255

static const char *states[] = { "OK", "WARNING", "CRITICAL", "UNKNOWN", "DEPENDENT", "UNKNOWN" };

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_NAGIOS_STATS_H_INCLUDED__ */
