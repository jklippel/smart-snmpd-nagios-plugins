/*
 * Copyright 2010, 2011 Matthias Haag, Jens Rehsack
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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_LOG4CPLUS_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_LOG4CPLUS_H_INCLUDED__

#include <smart-snmpd-nagios-plugins-build-defs.h>

#include <smart-snmpd-nagios-plugins/smart-snmpd-nagios-plugins.h>

#include <snmp_pp/snmp_pp.h>
#include <snmp_pp/log.h>

#include <log4cplus/logger.h>
#include <log4cplus/configurator.h>

#include <string>
#include <sstream>

using namespace log4cplus;
using namespace std;

namespace log4cplus
{
    /**
     * constant for user-defined log-level "EVENT" - between WARN and INFO
     */
    const LogLevel EVENT_LOG_LEVEL = (WARN_LOG_LEVEL + INFO_LOG_LEVEL) / 2;
    /**
     * constant string representation for the user-defined log-level "EVENT"
     */
    static log4cplus::tstring const EVENT_STRING(LOG4CPLUS_TEXT("EVENT"));
    /**
     * constant empty string
     */
    static log4cplus::tstring const empty_str;

    /**
     * conversion routine from log-level to string
     */
    static
    tstring const &
    eventToStringMethod(LogLevel ll)
    {
        if(ll == EVENT_LOG_LEVEL)
        {
            return EVENT_STRING;
        }
        else
        {
            return empty_str;
        }
    }

    /**
     * conversion routine from string to log-level
     */
    static
    LogLevel
    eventFromStringMethod(const tstring& s) 
    {
        if(s == EVENT_STRING)
            return EVENT_LOG_LEVEL;

        return NOT_SET_LOG_LEVEL;
    }

    /**
     * initializer class for user-defined log-level "EVENT"
     */
    class EventLogLevelInitializer
    {
    public:
        /**
         * constructor - registers user-defined log-level "EVENT" in LogLevelManager
         */
        EventLogLevelInitializer()
        {
            getLogLevelManager().pushToStringMethod(eventToStringMethod);
            getLogLevelManager().pushFromStringMethod(eventFromStringMethod);
        }
    };

    /**
     * instance to force user-defined log-level registration at program initialization
     */
    EventLogLevelInitializer eventLogLevelInitializer_;

}

/**
 * The LogEntry4CPlus class implements a log entry using log4cplus
 * 
 * @author Jens Rehsack
 * @version 0.1.0
 */
class LogEntry4CPlus
    : public NS_SNMP LogEntry
{
public:
    /**
     * Constructor with logger name, log class and severity level
     * 
     * @param n - The name of the logging module
     * @param t - The type of the log entry. The type is composed 
     *            by logical or the log entry class with a level
     *            of 0 up to 15. 
     * @note A error log of level 0 will stop program execution!
     */  
    LogEntry4CPlus(const char * const n, unsigned char t)
            : LogEntry(n, t)
            , mBufFull(false)
            , mOSS()
    {
    }

    /**
     * Destructor.
     */  
    virtual ~LogEntry4CPlus() {}

    /**
     * Initialize a new log entry, does nothing when using log4cplus
     */ 
    virtual void init(void) {}

    /**
     * Get the contents of this log entry.
     *
     * @return Current contents of this log entry.
     */ 
    virtual const char * get_value(void) const { return mOSS.str().c_str(); }

    /**
     * Get the log4cplus log-level from log-type of snmp++
     *
     * @return best matching log4cplus log-level for log-class from given log-type
     */
    inline static LogLevel getLog4CPlusLogLevel(unsigned char c)
    {
        switch( c & LOG_CLASS_MASK )
        {
        case ERROR_LOG:
            return ( ( c & LOG_LEVEL_MASK ) == 0 ) ? FATAL_LOG_LEVEL : ERROR_LOG_LEVEL;
            break;

        case WARNING_LOG:
            return WARN_LOG_LEVEL;
            break;

        case EVENT_LOG:
            return EVENT_LOG_LEVEL;
            break;

        case INFO_LOG:
            return INFO_LOG_LEVEL;
            break;

        case DEBUG_LOG:
            return DEBUG_LOG_LEVEL;
            break;

        case USER_LOG:
            return TRACE_LOG_LEVEL;
            break;
        }

        return ERROR_LOG_LEVEL; // default behaviour of snmp++
    }

protected:
    bool mBufFull;
    ostringstream mOSS;

    /**
     * Add a string to the log.
     *
     * @param s - A string value.
     * @return true if the value has been added and false if the log
     *         entry is full.
     */
    virtual bool add_string(const char *s)
    {
        if( mBufFull )
            return mBufFull;

        if( ( mOSS.str().length() + string(s).length() ) >= MAX_LOG_SIZE )
        {
            string substr( s, ( mOSS.str().length() + string(s).length() + 3 ) - MAX_LOG_SIZE );
            mOSS << substr << "...";
            mBufFull = true;
        }
        else
            mOSS << s;

        return mBufFull;
    }

    /**
     * Add an integer to the log.
     *
     * @param s - An integer value.
     * @return true if the value has been added and false if the log
     *         entry is full.
     */
    virtual bool add_integer(long l)
    {
        if( mBufFull )
            return mBufFull;

        mOSS << l;
        if( mOSS.str().length() >= MAX_LOG_SIZE )
            mBufFull = true;

        return mBufFull;
    }

    /**
     * Add the current time to the log.
     */
    virtual bool add_timestamp() { return mBufFull; }
};

/**
 * The AgentLog4CPlus class is an implementation of AgentLog which writes
 * log messages using the external library log4cplus from
 * http://log4cplus.sourceforge.net/.
 *
 * @author Jens Rehsack
 * @version 0.1.0
 */
class AgentLog4CPlus
    : public NS_SNMP AgentLog
{
public:
    /**
     * Default constructor, loads configured log4cplus configuration
     * and initializes connection to log4cplus.
     */ 
    AgentLog4CPlus()
        : AgentLog()
    {}

    /**
     * Destructor.
     */
    virtual ~AgentLog4CPlus() {}

    /**
     * Create a new LogEntry.
     *
     * @param name - The name of the logging module
     * @param t - The type of the log entry.
     * @return A new instance of LogEntry (or of a derived class).
     */
    virtual LogEntry * create_log_entry(const char * const name, unsigned char t) const
    {
        return new LogEntry4CPlus( name, t );
    }

    /**
     * Add a LogEntry to the receiver Log.
     *
     * @param log - A log entry.
     * @return The receiver log itself.
     */
    virtual AgentLog & operator += (const LogEntry *log)
    {
        Logger logger = Logger::getInstance( log->get_name() );
        logger.log( LogEntry4CPlus::getLog4CPlusLogLevel( log->get_type() ), log->get_value() );

        // check if critical error
        if ((log->get_class() == ERROR_LOG) && (log->get_level() == 0))
        {
            logger.log( INFO_LOG_LEVEL, "Exiting now", __FILE__, __LINE__ );
            raise(SIGTERM);
        }

        return *this;
    }

    /**
     * Check whether a logging for the given type of LogEntry
     * has to be done or not.
     *
     * @param type
     *    the type of the log entry. The type is composed 
     *    by logical or the log entry class with a level
     *    of 0 up to 15.
     * @return
     *    TRUE if logging is needed, FALSE otherwise.
     */
    virtual bool log_needed(const char * const n, unsigned char t) const
    {
        bool rc = AgentLog::log_needed(n, t);
        if( rc )
        {
            Logger logger = Logger::getInstance( n );
            rc = logger.isEnabledFor( LogEntry4CPlus::getLog4CPlusLogLevel(t) );
        }

        return rc;
    }
};

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_LOG4CPLUS_H_INCLUDED__ */
