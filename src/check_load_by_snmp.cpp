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
#include <smart-snmpd-nagios-plugins/nagios-stats.h>
#include <smart-snmpd-nagios-plugins/snmp-check.h>
#include <smart-snmpd-nagios-plugins/snmp-check-types.h>
#include <smart-snmpd-nagios-plugins/snmp-check-appl.h>

class LoadTuple
    : public boost::tuple< Threshold<double>, Threshold<double>, Threshold<double> >
{
public:
    LoadTuple( Threshold<double> const &load1 = Threshold<double>(), Threshold<double> const &load5 = Threshold<double>(),
              Threshold<double> const &load15 = Threshold<double>() )
        : boost::tuple< Threshold<double>, Threshold<double>, Threshold<double> >( load1, load5, load15 )
    {}

    inline bool has_load1() const { return !get<0>().empty(); }
    inline Threshold<double> load1() const { return get<0>(); }
    inline bool has_load5() const { return !get<1>().empty(); }
    inline Threshold<double> load5() const { return get<1>(); }
    inline bool has_load15() const { return !get<2>().empty(); }
    inline Threshold<double> load15() const { return get<2>(); }
};

inline bool operator >= (LoadTuple const &x, LoadTuple const &y)
{
    return ( x.load1() >= y.load1() )
        || ( x.load5() >= y.load5() )
        || ( x.load15() >= y.load15() );
}

/**
 * Overload the 'validate' function for the LoadTuple class.
 * It makes sure that value is either an integer value with
 * optional multiplier extension or a floating point value
 * with percent extenstion.  */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              LoadTuple *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);
    string::size_type sb, st = 0;
    Threshold<double> load1, load5, load15;

    while( st != string::npos )
    {
        boost::any tmp;

        if( st != 0 )
            ++st;
        st = s.find( ',', sb = st );

        string stmp( s, sb, st - sb );
        vector<string> vs;
        vs.push_back( stmp );

        if( load1.empty() )
        {
            validate( tmp, vs, &load1, 0);
            load1 = any_cast< Threshold<double> >(tmp);
            continue;
        }

        if( load5.empty() )
        {
            validate( tmp, vs, &load5, 0);
            load5 = any_cast< Threshold<double> >(tmp);
            continue;
        }

        if( load15.empty() )
        {
            validate( tmp, vs, &load15, 0);
            load15 = any_cast< Threshold<double> >(tmp);
            continue;
        }

        throw validation_error(validation_error::invalid_option_value, s);
    } while( st != string::npos );

    v = any( LoadTuple( load1, load5, load15 ) );
}

//! oids to request when smart-snmpd compatible mib is detected
static const Oid SmLoadOids[] = { SM_SYSTEM_LOAD1_REAL_INTEGER, SM_SYSTEM_LOAD5_REAL_INTEGER, SM_SYSTEM_LOAD15_REAL_INTEGER };
class SmartSnmpdLoadMibData
    : public SupportedMibData
{
public:
    SmartSnmpdLoadMibData()
        : SupportedMibData( make_vector<Oid, lengthof(SmLoadOids)>( SmLoadOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long long load1, load5, load15;
        if( SnmpComm::extract_value( vblist[0], load1 ) &&
            SnmpComm::extract_value( vblist[1], load5 ) &&
            SnmpComm::extract_value( vblist[2], load15 ) )
        {
            LoadTuple data( ((double)load1) / 100.0, ((double)load5) / 100.0, ((double)load15) / 100.0 );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "Machine load data incomplete or corrupt" );
        }
    }
};

//! oids to request when uc-davis compatible mib is detected
static const Oid UcdLoadOids[] = { UCD_LA_LOAD_INT ".1", UCD_LA_LOAD_INT ".2", UCD_LA_LOAD_INT ".3" };
class UcdavisLoadMibData
    : public SupportedMibData
{
public:
    UcdavisLoadMibData()
        : SupportedMibData( make_vector<Oid, lengthof(UcdLoadOids)>( UcdLoadOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        long load1, load5, load15;
        if( SnmpComm::extract_value( vblist[0], load1 ) &&
            SnmpComm::extract_value( vblist[1], load5 ) &&
            SnmpComm::extract_value( vblist[2], load15 ) )
        {
            LoadTuple data( ((double)load1) / 100.0, ((double)load5) / 100.0, ((double)load15) / 100.0 );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "Machine load data incomplete or corrupt" );
        }
    }
};

class SnmpLoadCheckAppl
    : public CheckPluginAppl< FetchStaticObjects, SnmpMandatoryWarnCritCheck< LoadTuple > >
{
public:
    SnmpLoadCheckAppl()
        : CheckPluginAppl< FetchStaticObjects, SnmpMandatoryWarnCritCheck< LoadTuple > >()
    {}

    virtual ~SnmpLoadCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
        mSupportedSnmpDaemons.push_back( IdentifyNetSnmpd );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
            return new SmartSnmpdLoadMibData();
        else if( identifiedDaemon.getName() == IdentifyNetSnmpd.getName() )
            return new UcdavisLoadMibData();

        throw unknown_daemon();
    }

    /**
     * generate nagios status message
     *
     * @param dataMap - values for nagios status message
     *
     * @return string containing the generated status message
     */
    string createResultMessage( DataMapType const &dataMap ) const
    {
        LoadTuple const &load = dataMap[ProveValueMapKey].as<LoadTuple>();
        string msg = string("load1: ") + to_string(load.load1()) + " "
                   + string("load5: ") + to_string(load.load5()) + " "
                   + string("load15: ") + to_string(load.load15()) + "";

        return msg;
    }

    /**
     * generate performance message for monitoring
     *
     * @param dataMap - values for performance message
     *
     * @return string containing the generated performance message
     */
    string createPerformanceMessage( DataMapType const &dataMap ) const
    {
        LoadTuple const &load = dataMap[ProveValueMapKey].as<LoadTuple>();
        LoadTuple const &warn = getWarn(), &crit = getCrit();

        string msg = string("load1=") + to_string(load.load1()) + ";" + to_string(warn.load1()) + ";" + to_string(crit.load1()) + ";0; "
                   + string("load5=") + to_string(load.load5()) + ";" + to_string(warn.load5()) + ";" + to_string(crit.load5()) + ";0; "
                   + string("load15=") + to_string(load.load15()) + ";" + to_string(warn.load15()) + ";" + to_string(crit.load15()) + ";0;";

        return msg;
    }

protected:
    virtual string const getCheckName() const { return "LOAD"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_load_by_snmp"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check load statistics via Simple Network Management Protocol"; }
};

int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpLoadCheckAppl checkAppl;
    string msg;

    try
    {
        checkAppl.setupFromCommandLine(argc, argv);
        checkAppl.configure();
        checkAppl.identifyDaemon(); // includes: getSupportedMibs();

        checkAppl.fetchData();
        checkAppl.convert();

        checkAppl.createMessages();
        rc = checkAppl.prove< std::greater_equal<LoadTuple> >();
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
