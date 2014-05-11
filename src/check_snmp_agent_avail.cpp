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

#undef loggerModuleName
#define loggerModuleName "nagiosplugins.check"

class invalid_type
    : public boost::program_options::invalid_option_value
{
public:
    invalid_type()
        : boost::program_options::invalid_option_value( "type" )
    {}
};

class AgentStatusTuple
    : public boost::tuple<TimestampThreshold, AbsoluteThreshold, AbsoluteThreshold>
{
public:
    AgentStatusTuple( TimestampThreshold const &updated = TimestampThreshold(), AbsoluteThreshold const &vsz_increases = AbsoluteThreshold(),
                 AbsoluteThreshold const &rsz_increases = AbsoluteThreshold() )
        : boost::tuple<TimestampThreshold, AbsoluteThreshold, AbsoluteThreshold>( updated, vsz_increases, rsz_increases )
    {}

    inline bool has_updated() const { return !get<0>().empty(); }
    inline TimestampThreshold updated() const { return get<0>(); }
    inline bool has_vsz_increases() const { return !get<1>().empty(); }
    inline AbsoluteThreshold vsz_increases() const { return get<1>(); }
    inline bool has_rsz_increases() const { return !get<2>().empty(); }
    inline AbsoluteThreshold rsz_increases() const { return get<2>(); }
};

class DaemonStatusCmp
    : public binary_function<AgentStatusTuple, AgentStatusTuple, bool>
{
public:
    DaemonStatusCmp()
        : mTimeCmp()
        , mIncsCmp()
    {}

    inline bool operator () (AgentStatusTuple const &c1, AgentStatusTuple const &c2) const
    {
        bool rc = false;

        rc |= mTimeCmp( c1.updated(), c2.updated() );
        rc |= mIncsCmp( c1.vsz_increases(), c2.vsz_increases() );
        rc |= mIncsCmp( c1.rsz_increases(), c2.rsz_increases() );

        return rc;
    }

protected:
    less_equal<TimestampThreshold> mTimeCmp;
    greater_equal<AbsoluteThreshold> mIncsCmp;
};

/**
 * Overload the 'validate' function for the AgentStatusTuple class.
 * It makes sure that value is either an integer value with
 * optional multiplier extension or a floating point value
 * with percent extenstion.  */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              AgentStatusTuple *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);
    string::size_type sb, st = 0;
    TimestampThreshold updated;
    AbsoluteThreshold vsz_incs, rsz_incs;

    while( st != string::npos )
    {
        boost::any tmp;

        if( st != 0 )
            ++st;
        st = s.find( ',', sb = st );

        string stmp( s, sb, st - sb );
        vector<string> vs;
        vs.push_back( stmp );

        if( updated.empty() )
        {
            validate( tmp, vs, &updated, 0);
            updated = any_cast<TimestampThreshold>(tmp);
            continue;
        }

        if( vsz_incs.empty() )
        {
            validate( tmp, vs, &vsz_incs, 0);
            vsz_incs = any_cast<AbsoluteThreshold>(tmp);
            continue;
        }

        if( rsz_incs.empty() )
        {
            validate( tmp, vs, &rsz_incs, 0);
            rsz_incs = any_cast<AbsoluteThreshold>(tmp);
            continue;
        }

        throw validation_error(validation_error::invalid_option_value, s);
    } while( st != string::npos );

    v = any( AgentStatusTuple( updated, vsz_incs, rsz_incs ) );
}

static const Oid SmDaemonOids[] = { SM_LAST_UPDATE_APP_MONITORING,
                                    SM_AGGREGATED_VIRTUAL_MEMORY_USAGE, SM_AGGREGATED_RESIDENT_MEMORY_USAGE,
                                    SM_CURRENT_VIRTUAL_MEMORY_USAGE, SM_CURRENT_RESIDENT_MEMORY_USAGE,
                                    SM_CURRENT_VIRTUAL_MEMORY_INCREASES, SM_CURRENT_RESIDENT_MEMORY_INCREASES };
class SmartSnmpdAgentMibData
    : public SupportedMibData
{
public:
    SmartSnmpdAgentMibData()
        : SupportedMibData( make_vector<Oid, lengthof(SmDaemonOids)>( SmDaemonOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long long last_update, aggregated_vsz, aggregated_rsz, current_vsz, current_rsz;
        unsigned long vsz_increases, rsz_increases;
        if( SnmpComm::extract_value( vblist[0], last_update ) &&
            SnmpComm::extract_value( vblist[1], aggregated_vsz ) &&
            SnmpComm::extract_value( vblist[2], aggregated_rsz ) &&
            SnmpComm::extract_value( vblist[3], current_vsz ) &&
            SnmpComm::extract_value( vblist[4], current_rsz ) &&
            SnmpComm::extract_value( vblist[5], vsz_increases ) &&
            SnmpComm::extract_value( vblist[6], rsz_increases ) )
        {
            AgentStatusTuple data( last_update, vsz_increases, rsz_increases );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );

            if( !aggregated_vsz )
                current_vsz = aggregated_vsz = 1;
            if( !aggregated_rsz )
                current_rsz = aggregated_rsz = 1;
            double rel_vsz = ( (((double)current_vsz) - ((double)aggregated_vsz)) * 100.0 ) / aggregated_vsz;
            double rel_rsz = ( (((double)current_rsz) - ((double)aggregated_rsz)) * 100.0 ) / aggregated_rsz;
            dataMap.insert( make_pair( "rel_vsz", rel_vsz ) );
            dataMap.insert( make_pair( "rel_rsz", rel_rsz ) );
        }
        else
        {
            throw snmp_bad_result( "Agent status data incomplete or corrupt" );
        }
    }
};

class SnmpAgentAvailCheckAppl
    : public CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< AgentStatusTuple > >
{
public:
    SnmpAgentAvailCheckAppl()
        : CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< AgentStatusTuple > >()
    {}

    virtual ~SnmpAgentAvailCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
            return new SmartSnmpdAgentMibData();
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
        AgentStatusTuple const &dt = dataMap[ProveValueMapKey].as<AgentStatusTuple>();
        string msg;

        if( dt.updated() > 0 )
        {
            time_t last_updated = time(NULL) - dt.updated();
            if( last_updated < 0 )
            {
                last_updated = 0;
            }
            msg = string("has been updated last time ") + to_string(last_updated / 60) + "m" + to_string(last_updated % 60) +"s ago";
        }
        else
        {
            msg = "has never been updated";
        }

        if( dt.has_vsz_increases() && dt.has_rsz_increases() )
        {
            msg += ", increased vsz " + to_string(dt.vsz_increases()) + " and rsz " + to_string(dt.rsz_increases()) + " times";
        }

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
        string msg = string("vsz memory variation=") + to_string(dataMap["rel_vsz"].as<double>()) + ";0;0 "
                   + string("rsz memory variation=") + to_string(dataMap["rel_rsz"].as<double>()) + ";0;0";

        return msg;
    }

protected:
    virtual string const getCheckName() const { return "AGENT"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_snmp_agent_avail"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check whether a suitable application monitoring agent is attached to snmpd or not"; }
};

int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpAgentAvailCheckAppl checkAppl;
    string msg;

    try
    {
        checkAppl.setupFromCommandLine(argc, argv);
        checkAppl.configure();
        checkAppl.identifyDaemon(); // includes: getSupportedMibs();

        checkAppl.fetchData();
        checkAppl.convert();

        checkAppl.createMessages();
        rc = checkAppl.prove< DaemonStatusCmp >();
    }
    catch(alarm_timeout_reached &a)
    {
        rc = STATE_CRITICAL;
        msg = a.what();
    }
    catch(snmp_error &s)
    {
        rc = STATE_CRITICAL;
        msg = s.what();
    }
    catch(std::exception& e)
    {
        cerr << (msg = e.what()) << endl;
    }

    return checkAppl.report(rc, msg);
}
