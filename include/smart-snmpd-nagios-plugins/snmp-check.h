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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_H_INCLUDED__

#include <smart-snmpd-nagios-plugins/snmp-pp-std.h>
#include <smart-snmpd-nagios-plugins/snmp-comm.h>
#include <smart-snmpd-nagios-plugins/nagios-stats.h>

#include <boost/lexical_cast.hpp>

using namespace boost;

#include <string>
#include <iostream>
#include <iomanip>

using namespace std;

#undef loggerModuleName
#define loggerModuleName "nagiosplugins.snmpcheck"

template < class T >
class SnmpWarnCritCheck
{
public:
    typedef T CheckType;

    virtual ~SnmpWarnCritCheck() {}

    void add_check_options(options_description &checkopts) const
    {
        checkopts.add_options()
            ("warn,w", value<T>(), "warn threshold")
            ("crit,c", value<T>(), "crit threshold")
            ;
    }

    void validate_options(variables_map const &vm) const { (void)vm; }

    void configure(variables_map const &vm)
    {
        if( ( vm.count("warn") != 0 ) && !vm["warn"].defaulted() )
            mWarn = vm["warn"].as<T>();
        if( ( vm.count("crit") != 0 ) && !vm["crit"].defaulted() )
            mCrit = vm["crit"].as<T>();
    }

    T const & getWarn() const { return mWarn; }
    T const & getCrit() const { return mCrit; }

    /**
     * prove values got from snmpd against comparators given by caller
     *
     * Note: This method must not be overridden but specialized when different
     * behavior is desired.
     *
     * @param v - comparator filled with the values from snmpd
     *
     * @return nagios status code
     */
    template < class Cmp >
    int prove( T const &val, Cmp const &cmp = Cmp() ) const
    {
        if( cmp( val, mCrit ) )
            return STATE_CRITICAL;
        if( cmp( val, mWarn  ) )
            return STATE_WARNING;

        return STATE_OK;
    }

protected:
    T mWarn;
    T mCrit;
};

template < class T >
class SnmpMandatoryWarnCritCheck
    : public SnmpWarnCritCheck<T>
{
public:
    virtual ~SnmpMandatoryWarnCritCheck() {}

    void configure(variables_map const &vm)
    {
        this->mWarn = vm["warn"].as<T>();
        this->mCrit = vm["crit"].as<T>();
    }

    void validate_options(variables_map const &vm) const
    {
        option_required( vm, "warn" );
        option_required( vm, "crit" );
    }
};

class SnmpBoolCritCheck
{
public:
    typedef bool CheckType;

    virtual ~SnmpBoolCritCheck() {}

    void add_check_options(options_description &checkopts) const { (void)checkopts; }
    void validate_options(variables_map const &vm) const { (void)vm; }
    void configure(variables_map const &vm) { (void)vm; }

    template < class Cmp >
    int prove( bool val, Cmp const &cmp = Cmp() ) const
    {
        if( cmp( val, true ) )
            return STATE_CRITICAL;

        return STATE_OK;
    }
};

#undef loggerModuleName

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_H_INCLUDED__ */
