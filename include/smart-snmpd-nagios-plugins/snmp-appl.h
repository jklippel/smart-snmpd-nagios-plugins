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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_APPL_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_APPL_H_INCLUDED__

#include <smart-snmpd-nagios-plugins/snmp-comm.h>
#include <smart-snmpd-nagios-plugins/nagios-stats.h>
#include <smart-snmpd-nagios-plugins/snmp-daemon-identifiers.h>

#include <snmp_pp/snmp_pp.h>

#ifndef _NO_LOGGING
#include <smart-snmpd-nagios-plugins/log4cplus.h>
#endif

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/tokenizer.hpp>
#include <boost/token_functions.hpp>

using namespace boost;
using namespace boost::program_options;

#include <string>

using namespace std;

#undef loggerModuleName
#define loggerModuleName "nagiosplugins.snmpappl"

/**
 * base class for snmp applications
 *
 * This is a base class for snmp applications (read: applications which
 * wants to communicate with an snmp daemon).
 */
class SnmpAppl
{
public:
    /**
     * default constructor
     */
    SnmpAppl()
        : mCmndlineValuesMap()
        , mSnmpComm()
    {}

    /**
     * destructs application objects
     */
    virtual ~SnmpAppl() {}

    /**
     * adds the supported general options to the given options_description instance
     *
     * @param generalopts - options_description instance to add the general options to
     */
    virtual void add_general_options(options_description &generalopts) const
    {
        generalopts.add_options()
            ("help,h", "produce a help message")
            ("version,v", "output the version number")
#ifndef _NO_LOGGING
            ("debug-level,d", value<int>()->default_value(0), "sets debug level (0..4)")
#endif
            ;
    }

    /**
     * adds the supported snmp options to the given options_description instance
     *
     * @param snmpopts - options_description instance to add the snmp options to
     */
    virtual void add_snmp_options(options_description &snmpopts) const
    {
        mSnmpComm.add_snmp_options(snmpopts);
    }

    /**
     * initializes program options and return them
     *
     * @return options_description - the common program options
     */
    virtual options_description get_options() const
    {
        options_description general("General options");
        add_general_options( general );
        options_description snmpopts("SNMP options");
        add_snmp_options( snmpopts );

        // Declare an options description instance which will include
        // all the options
        options_description all("Allowed options");
        all.add(general).add(snmpopts);

        return all;
    }

    /**
     * validate got options and option parameters
     *
     * This method approves the integrity of the options and option
     * parameters parsed from command line (etc.) held in member
     * attribute mCmndlineValuesMap and throws an appropriate exceptions
     * when something went wrong. Typical exceptions are from type
     * boost::program_options::error.
     */
    virtual void validate_options() const
    {
        mSnmpComm.validate_options( mCmndlineValuesMap );
    }

    /**
     * parses options from argc/argv and built variables_map instance from it
     *
     * @param argc - argument count
     * @param argv - argument values
     */
    virtual void setupFromCommandLine(int argc, char *argv[])
    {
        options_description all = get_options();
        store( parse_command_line(argc, argv, all), mCmndlineValuesMap );

        if( mCmndlineValuesMap.count("help") ) 
        {
            cout << all;
            exit(0);
        }
        if( mCmndlineValuesMap.count("version") )
            version(0);

        validate_options();
    }

#ifndef _NO_LOGGING
    /**
     * setup logging environment depending on the specified verbosity level
     *
     * @param loglevel - sensitivity of output
     */
    virtual void configure_logging(int loglevel) const
    {
        log4cplus::helpers::Properties properties;
        const char *log_profile;

        if( loglevel == 0 )
        {
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.snmp++"),
                                   LOG4CPLUS_TEXT("WARN, STDOUT"));
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.nagiosplugins"),
                                   LOG4CPLUS_TEXT("WARN, STDOUT"));
            log_profile = "quiet";
        }
        else if( loglevel == 1 )
        {
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.snmp++"),
                                   LOG4CPLUS_TEXT("WARN, STDOUT"));
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.nagiosplugins"),
                                   LOG4CPLUS_TEXT("INFO, STDOUT"));
            log_profile = "std";
        }
        else if( loglevel == 2 )
        {
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.snmp++"),
                                   LOG4CPLUS_TEXT("EVENT, STDOUT"));
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.nagiosplugins"),
                                   LOG4CPLUS_TEXT("INFO, STDOUT"));
            log_profile = "full";
        }
        else if( loglevel == 3 )
        {
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.snmp++"),
                                   LOG4CPLUS_TEXT("INFO, STDOUT"));
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.logger.nagiosplugins"),
                                   LOG4CPLUS_TEXT("DEBUG, STDOUT"));
            log_profile = "debug";
        }
        else
        {
            properties.setProperty(LOG4CPLUS_TEXT("log4cplus.rootLogger"),
                                   LOG4CPLUS_TEXT("DEBUG, STDOUT"));
            log_profile = "schwafel";
        }
        properties.setProperty(LOG4CPLUS_TEXT("log4cplus.appender.STDOUT"),
                               LOG4CPLUS_TEXT("log4cplus::ConsoleAppender"));

        PropertyConfigurator configurator( properties );
        configurator.configure();

        AgentLog4CPlus *al = new AgentLog4CPlus();
        if( !al )
        {
            // this goes to stderr using default AgentLogImpl
            LOG_BEGIN( loggerModuleName, ERROR_LOG | 0 );
            LOG("Out of memory instantiating new AgentLogImpl");
            LOG_END;

            throw bad_alloc();
        }
        if( al != DefaultLog::init_ts( al ) )
        {
            DefaultLog::init( al );
        }
        DefaultLog::log ()->set_profile( log_profile );
    }
#endif

    /**
     * displays application name including version and exit
     *
     * @param exit_code - value to pass to exit()
     */
    void version(int exit_code = 0) const
    {
        ostream &os = exit_code ? cerr : cout;

        os << getApplName() << " " << getApplVersion() << " " << getApplDescription() << endl;

        exit(exit_code);
    }

    /**
     * configures application
     */
    void configure()
    {
#ifndef _NO_LOGGING
        configure_logging( mCmndlineValuesMap["debug-level"].as<int>() );
#endif

        mSnmpComm.configure( mCmndlineValuesMap );
    }

protected:
    /**
     * parsed variables from command line (or their default values, respectively)
     */
    variables_map mCmndlineValuesMap;
    /**
     * check object - must implement SnmpCheck compatible API
     * @see SnmpCheck
     */
    SnmpComm mSnmpComm;

    /**
     * contains the application name (e.g. check_cpu_by_snmp)
     */
    virtual string const getApplName() const = 0;
    /**
     * contains the application version (currently common value for all checks used)
     */
    virtual string const getApplVersion() const = 0;
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const = 0;
};

#undef loggerModuleName

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_SNMP_APPL_H_INCLUDED__ */
