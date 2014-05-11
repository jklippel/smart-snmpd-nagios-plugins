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

static const Oid SmSwapOids[] = { SM_FREE_MEMORY_SWAP, SM_USED_MEMORY_SWAP, SM_TOTAL_MEMORY_SWAP };
class SmartSnmpdSwapMibData
    : public SupportedMibData
{
public:
    SmartSnmpdSwapMibData()
        : SupportedMibData( make_vector<Oid, lengthof(SmSwapOids)>( SmSwapOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long long avail, used, total;
        if( SnmpComm::extract_value( vblist[0], avail ) &&
            SnmpComm::extract_value( vblist[1], used ) &&
            SnmpComm::extract_value( vblist[2], total ) )
        {
            SizeThreshold data( BytesThreshold( avail ), RelativeThreshold( ((double)used / total) ) );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
            dataMap.insert( make_pair( "avail", avail ) );
            dataMap.insert( make_pair( "total", total ) );
        }
        else
        {
            throw snmp_bad_result( "Swap statistics incomplete or corrupt" );
        }
    }
};

static const Oid UcdSwapOids[] = { UCD_MEM_AVAIL_SWAP ".0", UCD_MEM_TOTAL_SWAP ".0" };
class UcdavisSwapMibData
    : public SupportedMibData
{
public:
    UcdavisSwapMibData()
        : SupportedMibData( make_vector<Oid, lengthof(UcdSwapOids)>( UcdSwapOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        unsigned long avail, total;
        if( SnmpComm::extract_value( vblist[0], avail ) &&
            SnmpComm::extract_value( vblist[1], total ) )
        {
            SizeThreshold data( BytesThreshold( ((unsigned long long)avail) * 1024 ), RelativeThreshold( ((double)(total - avail) / total) ) );

            dataMap.insert( make_pair( ProveValueMapKey, data ) );
            dataMap.insert( make_pair( "avail", any( (unsigned long long)avail * 1024 ) ) );
            dataMap.insert( make_pair( "total", any( (unsigned long long)total * 1024 ) ) );
        }
        else
        {
            throw snmp_bad_result( "Swap statistics incomplete or corrupt" );
        }
    }
};

class SnmpSwapCheckAppl
    : public CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< SizeThreshold > >
{
public:
    SnmpSwapCheckAppl()
        : CheckPluginAppl< FetchStaticObjects, SnmpWarnCritCheck< SizeThreshold > >()
    {}

    virtual ~SnmpSwapCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
        mSupportedSnmpDaemons.push_back( IdentifyNetSnmpd );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
            return new SmartSnmpdSwapMibData();
        else if( identifiedDaemon.getName() == IdentifyNetSnmpd.getName() )
            return new UcdavisSwapMibData();

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
        unsigned long long mb = 1024ULL * 1024;
        unsigned long long avail = dataMap["avail"].as<unsigned long long>();
        unsigned long long total = dataMap["total"].as<unsigned long long>();
        string msg = string("avail: ") + to_string(avail/mb) + "M "
                   + string("total: ") + to_string(total/mb) + "M";

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
        unsigned long long kb = 1024ULL;
        unsigned long long avail = dataMap["avail"].as<unsigned long long>();
        unsigned long long total = dataMap["total"].as<unsigned long long>();
        string msg = string("iso.3.6.1.4.1.2021.4.4.0=") + to_string(avail / kb) + " "
                   + string("iso.3.6.1.4.1.2021.4.3.0=") + to_string(total / kb);

        return msg;
    }

protected:
    virtual string const getCheckName() const { return "SWAP"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_swap_by_snmp"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check swap statistics via Simple Network Management Protocol"; }
};

int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpSwapCheckAppl checkAppl;
    string msg;

    try
    {
        checkAppl.setupFromCommandLine(argc, argv);
        checkAppl.configure();
        checkAppl.identifyDaemon(); // includes: getSupportedMibs();

        checkAppl.fetchData();
        checkAppl.convert();

        checkAppl.createMessages();
        rc = checkAppl.prove< AbsoluteRelativeCmp<> >();
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
