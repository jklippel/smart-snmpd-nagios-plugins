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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_PROGRAM_OPTIONS_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_PROGRAM_OPTIONS_H_INCLUDED__

#include <smart-snmpd-nagios-plugins/snmp-pp-std.h>
#include <smart-snmpd-nagios-plugins/nagios-stats.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/tokenizer.hpp>
#include <boost/token_functions.hpp>

using namespace boost;
using namespace boost::program_options;

#include <string>
#include <iostream>
#include <iomanip>

using namespace std;

//!
typedef boost::program_options::error option_error;

/**
 * Auxiliary functions for checking input for validity.
 */

/**
 * Function used to check that 'opt1' and 'opt2' are not specified
 * at the same time.
 */
void conflicting_options(const variables_map& vm, 
                         const char* opt1, const char* opt2)
{
    if( vm.count(opt1) && !vm[opt1].defaulted() 
        && vm.count(opt2) && !vm[opt2].defaulted() )
    {
        throw option_error(string("Conflicting options '")
                           + opt1 + "' and '" + opt2 + "'.");
    }
}

/**
 * Function used to check that of 'for_what' is specified, then
 * 'req_opt' is specified too.
 */
void option_dependency(const variables_map& vm,
                        const char* for_what, const char* req_opt)
{
    if( vm.count(for_what) && !vm[for_what].defaulted() )
    {
        if (vm.count(req_opt) == 0 || vm[req_opt].defaulted())
        {
            throw option_error(string("Option '") + for_what
                               + "' requires option '" + req_opt + "'.");
        }
    }
}

/**
 * Function used to check that of 'for_what' is specified with a specific
 * value, then 'req_opt' is specified too.
 */
template <class T>
void option_dependency(const variables_map& vm, const char* for_what, T const &v, const char* req_opt)
{
    if( vm.count(for_what) && !vm[for_what].defaulted() &&  v == vm[for_what].as<T>() )
    {
        if( vm.count(req_opt) == 0 || vm[req_opt].defaulted() )
        {
            throw option_error(string("Option '") + for_what + "' with value '"
                               + snmp_version_to_string(v) + "' requires option '" + req_opt + "'.");
        }
    }
}

/**
 * Function used to check that 'req_opt' is specified
 */
void option_required(variables_map const &vm, const char *req_opt)
{
    if( ( vm.count(req_opt) == 0 ) || vm[req_opt].defaulted() )
        throw required_option( req_opt );
}

/**
 * Function used to check that one of 'req_opt' is specified
 */
void option_required(variables_map const &vm, const vector<const char *> &req_opt, bool all = false)
{
    string names;
    for( vector<const char *>::const_iterator i = req_opt.begin(); i != req_opt.end(); ++i )
    {
        if( ( vm.count(*i) ) && !vm[*i].defaulted() )
        {
            if( all )
                continue;
            return;
        }
        if( !names.empty() )
        {
            if( (i + 1) == req_opt.end() )
            {
                if( all )
                    names += " or ";
                else
                    names += " and ";
            }
            else
                names += ", ";
        }
        names += *i;
    }
    if( !names.empty() )
        throw required_option( names );
}

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_PROGRAM_OPTIONS_H_INCLUDED__ */
