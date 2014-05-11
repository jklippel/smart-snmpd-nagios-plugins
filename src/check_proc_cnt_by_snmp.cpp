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

static const Oid SmProcCntOids[] = { SM_PROCESS_TOTAL };
class SmartSnmpdProcessCountMibData
    : public SupportedMibData
{
public:
    SmartSnmpdProcessCountMibData()
        : SupportedMibData( make_vector<Oid, lengthof(SmProcCntOids)>( SmProcCntOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long long proc_cnt;
        if( SnmpComm::extract_value( vblist[0], proc_cnt ) )
        {
            AbsoluteThreshold data( proc_cnt );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "Process count incomplete (o.O) or corrupt" );
        }
    }
};

static const Oid HrProcCntOids[] = { HR_SYSTEM_PROCESSES ".0" };
class HostResourcesProcessCountMibData
    : public SupportedMibData
{
public:
    HostResourcesProcessCountMibData()
        : SupportedMibData( make_vector<Oid, lengthof(HrProcCntOids)>( HrProcCntOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long proc_cnt;
        if( SnmpComm::extract_value( vblist[0], proc_cnt ) )
        {
            AbsoluteThreshold data( proc_cnt );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "Process count incomplete (o.O) or corrupt" );
        }
    }
};

class SnmpProcessCountCheckAppl
    : public CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< AbsoluteThreshold > >
{
public:
    SnmpProcessCountCheckAppl()
        : CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< AbsoluteThreshold > >()
    {}

    virtual ~SnmpProcessCountCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
        mSupportedSnmpDaemons.push_back( IdentifyNetSnmpd );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
            return new SmartSnmpdProcessCountMibData();
        else if( identifiedDaemon.getName() == IdentifyNetSnmpd.getName() )
            return new HostResourcesProcessCountMibData();

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
        string msg = to_string(dataMap[ProveValueMapKey].as<AbsoluteThreshold>()) + " procs currently running";

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
        string msg = string("procs=") + to_string(dataMap[ProveValueMapKey].as<AbsoluteThreshold>()) + ";";

        return msg;
    }

protected:
    virtual string const getCheckName() const { return "PROCS"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_proc_cnt_by_snmp"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check count of running processes via Simple Network Management Protocol"; }
};

int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpProcessCountCheckAppl checkAppl;
    string msg;

    try
    {
        checkAppl.setupFromCommandLine(argc, argv);
        checkAppl.configure();
        checkAppl.identifyDaemon(); // includes: getSupportedMibs();

        checkAppl.fetchData();
        checkAppl.convert();

        checkAppl.createMessages();
        rc = checkAppl.prove< std::greater_equal<AbsoluteThreshold> >();
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
