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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_PP_STD_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_PP_STD_H_INCLUDED__

#include <snmp_pp/snmp_pp.h>

#include <boost/program_options/errors.hpp>

using namespace boost;
using namespace boost::program_options;

#include <smart-snmpd-nagios-plugins/std-ext.h>

/**
 * helper function to cast string into snmp_version
 */
inline static
snmp_version
str_to_snmp_version(string const &s)
{
    if( s == "1" )
        return version1;
    else if( ( s == "2c" ) || ( s == "2C" ) )
        return version2c;
    else if( s == "3" )
        return version3;
    else
        throw invalid_value_execption(s + " -> snmp_version");
}

/**
 * helper function to cast snmp_version into string
 */
inline static
string
snmp_version_to_string(snmp_version const &v)
{
    if( v == version1 )
        return "1";
    if( v == version2c )
        return "2c";
    if( v == version3 )
        return "3";

    throw invalid_value_execption("Invalid snmp_version value");
}

/**
 * overloaded stream output operator for snmp_version objects
 */
inline ostream &
operator << (ostream &os, snmp_version const &v)
{
    return os << snmp_version_to_string(v);
}

/**
 * overloaded stream input operator for snmp_version objects
 */
inline istream &
operator >> (istream &is, snmp_version &v)
{
    string s;
    is >> s;
    v = str_to_snmp_version( s );
    return is;
}

/**
 * overloaded stream output operator for SnmpSyntax objects
 */
inline ostream &
operator << (ostream &os, SnmpSyntax const &syn)
{
    return os << syn.get_printable();
}

/**
 * overloaded stream input operator for OctetStr objects
 */
inline istream &
operator >> (istream &is, OctetStr &o)
{
    string s;
    is >> s;
    o = s.c_str();
    if( !o.valid() )
        throw invalid_value_execption(s + " -> OctetStr");
    return is;
}

/**
 * overloaded stream input operator for OctetStr objects
 */
inline istream &
operator >> (istream &is, Oid &oid)
{
    string s;
    is >> s;
    oid = s.c_str();
    if( !oid.valid() )
        throw invalid_value_execption(s + " -> Oid");
    return is;
}

/**
 * overloaded stream input operator for Address objects
 */
inline istream &
operator >> (istream &is, Address &addr)
{
    string s;
    is >> s;
    addr = s.c_str();
    if( !addr.valid() )
        throw invalid_value_execption(s + " -> Address");
    return is;
}

/**
 * overloaded stream input operator for SnmpInt32 objects
 */
inline istream &
operator >> (istream &is, SnmpInt32 &i32)
{
    long il;
    is >> il;
    i32 = il;
    return is;
}

/**
 * overloaded stream input operator for SnmpUInt32 objects
 */
inline istream &
operator >> (istream &is, SnmpUInt32 &ui32)
{
    unsigned long ul;
    is >> ul;
    ui32 = ul;
    return is;
}

/**
 * overloaded stream input operator for Counter64 objects
 */
inline istream &
operator >> (istream &is, Counter64 &c64)
{
    unsigned long long ull;
    is >> ull;
    c64 = ull;
    return is;
}

namespace boost
{

template<>
std::string
lexical_cast<std::string>( snmp_version const &v )
{
    return snmp_version_to_string(v);
}

}

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_SNMP_PP_STD_H_INCLUDED__ */
