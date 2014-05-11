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

static const Oid SmUserCntOids[] = { SM_USER_LOGIN_COUNT };
class SmartSnmpdUserCountMibData
    : public SupportedMibData
{
public:
    SmartSnmpdUserCountMibData()
        : SupportedMibData( make_vector<Oid, lengthof(SmUserCntOids)>( SmUserCntOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long long user_cnt;
        if( SnmpComm::extract_value( vblist[0], user_cnt ) )
        {
            AbsoluteThreshold data( user_cnt );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "User count incomplete (o.O) or corrupt" );
        }
    }
};

static const Oid HrUserCntOids[] = { HR_SYSTEM_NUM_USERS ".0" };
class HostResourcesUserCountMibData
    : public SupportedMibData
{
public:
    HostResourcesUserCountMibData()
        : SupportedMibData( make_vector<Oid, lengthof(HrUserCntOids)>( HrUserCntOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long user_cnt;
        if( SnmpComm::extract_value( vblist[0], user_cnt ) )
        {
            AbsoluteThreshold data( user_cnt );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
        }
        else
        {
            throw snmp_bad_result( "User count incomplete (o.O) or corrupt" );
        }
    }
};

class SnmpUserCountCheckAppl
    : public CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< AbsoluteThreshold > >
{
public:
    SnmpUserCountCheckAppl()
        : CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< AbsoluteThreshold > >()
    {}

    virtual ~SnmpUserCountCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
        mSupportedSnmpDaemons.push_back( IdentifyNetSnmpd );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
            return new SmartSnmpdUserCountMibData();
        else if( identifiedDaemon.getName() == IdentifyNetSnmpd.getName() )
            return new HostResourcesUserCountMibData();

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
        string msg = to_string(dataMap[ProveValueMapKey].as<AbsoluteThreshold>()) + " users currently logged in";

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
	unsigned long long warn = getWarn(), crit = getCrit();
        string msg = string("users=") + to_string(dataMap[ProveValueMapKey].as<AbsoluteThreshold>()) + ";" + to_string(warn) + ";" + to_string(crit) + ";0";

        return msg;
    }

protected:
    virtual string const getCheckName() const { return "USERS"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_user_cnt_by_snmp"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check logged in user count via Simple Network Management Protocol"; }
};

int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpUserCountCheckAppl checkAppl;
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
