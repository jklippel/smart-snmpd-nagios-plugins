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

#include <smart-snmpd-nagios-plugins-build-defs.h>
#include <smart-snmpd-nagios-plugins/smart-snmpd-nagios-plugins.h>

#include <smart-snmpd-nagios-plugins/oids.h>
#include <smart-snmpd-nagios-plugins/snmp-check.h>
#include <smart-snmpd-nagios-plugins/snmp-check-types.h>
#include <smart-snmpd-nagios-plugins/snmp-check-appl.h>

/**
 * CPU data tuple
 *
 * contains up to 4 values for user time, system time, idle time and I/O wait time
 */
class CpuTuple
    : public boost::tuple<AbsoluteThreshold, AbsoluteThreshold, AbsoluteThreshold, AbsoluteThreshold>
{
public:
    /**
     * standard constructor
     *
     * @param user - optional initial value for user time
     * @param system - optional initial value for system time
     * @param idle - optional initial value for idle time
     * @param wait - optional initial value for I/O wait time
     */
    CpuTuple( AbsoluteThreshold const &user = AbsoluteThreshold(), AbsoluteThreshold const &system = AbsoluteThreshold(),
              AbsoluteThreshold const &idle = AbsoluteThreshold(), AbsoluteThreshold const &wait = AbsoluteThreshold() )
        : boost::tuple<AbsoluteThreshold, AbsoluteThreshold, AbsoluteThreshold, AbsoluteThreshold>( user, system, idle, wait )
    {}

    //! tells if user time is set
    inline bool has_user() const { return !get<0>().empty(); }
    //! delivers user time (or default: 0, if unset)
    inline AbsoluteThreshold user() const { return get<0>(); }
    //! tells if system time is set
    inline bool has_system() const { return !get<1>().empty(); }
    //! delivers system time (or default: 0, if unset)
    inline AbsoluteThreshold system() const { return get<1>(); }
    //! tells if idle time is set
    inline bool has_idle() const { return !get<2>().empty(); }
    //! delivers idle time (or default: 0, if unset)
    inline AbsoluteThreshold idle() const { return get<2>(); }
    //! tells if wait time is set
    inline bool has_wait() const { return !get<3>().empty(); }
    //! delivers wait time (or default: 0, if unset)
    inline AbsoluteThreshold wait() const { return get<3>(); }
};

/**
 * compares two user data tuples
 *
 * @param x - first operand to be compared
 * qparam y - second operand to be compared
 *
 * @return true when the first tuple contains at least one value which is greater or equal to the equivalent value in the second tuple
 */
inline bool operator >= (CpuTuple const &x, CpuTuple const &y)
{
    return ( x.user() >= y.user() )
        || ( x.system() >= y.system() )
        || ( x.idle() >= y.idle() )
        || ( x.wait() >= y.wait() );
}

/**
 * Overload the 'validate' function for the CpuTuple class.
 * It makes sure that value is either an integer value with
 * optional multiplier extension or a floating point value
 * with percent extenstion.
 */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              CpuTuple *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);
    string::size_type sb, st = 0;
    AbsoluteThreshold user, system, idle, wait;

    while( st != string::npos )
    {
        boost::any tmp;

        if( st != 0 )
            ++st;
        st = s.find( ',', sb = st );

        string stmp( s, sb, st - sb );
        vector<string> vs;
        vs.push_back( stmp );

        if( user.empty() )
        {
            validate( tmp, vs, &user, 0);
            user = any_cast<AbsoluteThreshold>(tmp);
            continue;
        }

        if( system.empty() )
        {
            validate( tmp, vs, &system, 0);
            system = any_cast<AbsoluteThreshold>(tmp);
            continue;
        }

        if( idle.empty() )
        {
            validate( tmp, vs, &idle, 0);
            idle = any_cast<AbsoluteThreshold>(tmp);
            continue;
        }

        if( wait.empty() )
        {
            validate( tmp, vs, &wait, 0);
            wait = any_cast<AbsoluteThreshold>(tmp);
            continue;
        }

        throw validation_error(validation_error::invalid_option_value, s);
    } while( st != string::npos );

    v = any( CpuTuple( user, system, idle, wait ) );
}

//! oids to request when smart-snmpd compatible mib is detected
static const Oid SmCpuOids[] = { SM_CPU_USER_TIME_INTERVAL, SM_CPU_KERNEL_TIME_INTERVAL, SM_CPU_IDLE_TIME_INTERVAL, SM_CPU_TOTAL_TIME_INTERVAL };
class SmartSnmpdCpuMibData
    : public SupportedMibData
{
public:
    SmartSnmpdCpuMibData()
        : SupportedMibData( make_vector<Oid, lengthof(SmCpuOids)>( SmCpuOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long long user, kernel, idle, total;
        if( SnmpComm::extract_value( vblist[0], user ) &&
            SnmpComm::extract_value( vblist[1], kernel ) &&
            SnmpComm::extract_value( vblist[2], idle ) &&
            SnmpComm::extract_value( vblist[3], total ) )
        {
            CpuTuple data;
            if( 0 == total )
                data = CpuTuple( 0, 0, 0 );
            else
                data = CpuTuple( (user * 100) / total, (kernel * 100) / total, (idle * 100) / total );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "CPU usage data incomplete or corrupt" );
        }
    }
};

//! oids to request when uc-davis compatible mib is detected
static const Oid UcdCpuOids[] = { UCD_SS_CPU_USER ".0", UCD_SS_CPU_SYSTEM ".0", UCD_SS_CPU_IDLE ".0" };
class UcdavisCpuMibData
    : public SupportedMibData
{
public:
    UcdavisCpuMibData()
        : SupportedMibData( make_vector<Oid, lengthof(UcdCpuOids)>( UcdCpuOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long user, kernel, idle;
        if( SnmpComm::extract_value( vblist[0], user ) &&
            SnmpComm::extract_value( vblist[1], kernel ) &&
            SnmpComm::extract_value( vblist[2], idle ) )
        {
            CpuTuple data( user, kernel, idle );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "CPU usage data incomplete or corrupt" );
        }
    }
};

class SnmpCpuCheckAppl
    : public CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< CpuTuple > >
{
public:
    SnmpCpuCheckAppl()
        : CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< CpuTuple > >()
    {}

    virtual ~SnmpCpuCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
        mSupportedSnmpDaemons.push_back( IdentifyNetSnmpd );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
            return new SmartSnmpdCpuMibData();
        else if( identifiedDaemon.getName() == IdentifyNetSnmpd.getName() )
            return new UcdavisCpuMibData();

        throw unknown_daemon();
    }

    /**
     * generate nagios status message
     *
     * @param cpu - values for nagios status message
     *
     * @return string containing the generated status message
     */
    string createResultMessage( DataMapType const &dataMap ) const
    {
        CpuTuple const & cpu = dataMap[ProveValueMapKey].as<CpuTuple>();
        string msg = string("user: ") + to_string(cpu.user()) + "% "
                   + string("system: ") + to_string(cpu.system()) + "% "
                   + string("idle: ") + to_string(cpu.idle()) + "% "
                   + string("wait: ") + to_string(100 - (cpu.user() + cpu.system() + cpu.idle())) + "%";

        return msg;
    }

    /**
     * generate performance message for monitoring
     *
     * @param cpu - values for performance message
     *
     * @return string containing the generated performance message
     */
    string createPerformanceMessage( DataMapType const &dataMap ) const
    {
        CpuTuple const & cpu = dataMap[ProveValueMapKey].as<CpuTuple>();
        string msg = string("iso.3.6.1.4.1.2021.11.9.0=") + to_string(cpu.user()) + " "
                   + string("iso.3.6.1.4.1.2021.11.10.0=") + to_string(cpu.system()) + " "
                   + string("iso.3.6.1.4.1.2021.11.11.0=") + to_string(cpu.idle());

        return msg;
    }

protected:
    virtual string const getCheckName() const { return "CPU"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_cpu_by_snmp"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check CPU statistics via Simple Network Management Protocol"; }
};

int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpCpuCheckAppl checkAppl;
    string msg;

    try
    {
        checkAppl.setupFromCommandLine(argc, argv);
        checkAppl.configure();
        checkAppl.identifyDaemon(); // includes: getSupportedMibs();

        checkAppl.fetchData();
        checkAppl.convert();

        checkAppl.createMessages();
        rc = checkAppl.prove< std::greater_equal<CpuTuple> >();
    }
    catch(alarm_timeout_reached &a)
    {
        rc = STATE_UNKNOWN;
        msg = a.what();
    }
    catch(snmp_error &s)
    {
        rc = STATE_UNKNOWN;
        msg = s.what();
    }
    catch(std::exception& e)
    {
        cerr << (msg = e.what()) << endl;
    }

    return checkAppl.report(rc, msg);
}
