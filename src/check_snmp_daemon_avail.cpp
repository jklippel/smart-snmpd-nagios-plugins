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

class SnmpDaemonAvailCheckAppl
    : public CheckPluginAppl< FetchStaticObjects, SnmpBoolCritCheck >
{
public:
    SnmpDaemonAvailCheckAppl()
        : CheckPluginAppl< FetchStaticObjects, SnmpBoolCritCheck >()
    {}

    virtual ~SnmpDaemonAvailCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
        mSupportedSnmpDaemons.push_back( IdentifyNetSnmpd );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        (void)identifiedDaemon;
        return (SupportedMibDataType *)1; // XXX I really know what I'm doing here, please do not repeat
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
        (void)dataMap;
        return mIdentifiedSnmpDaemon->getName();
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
        (void)dataMap;
        return "";
    }

protected:
    virtual string const getCheckName() const { return "DAEMON"; }
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
    virtual string const getApplDescription() const { return "Check whether a suitable snmpd is available or not"; }
};


int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpDaemonAvailCheckAppl checkAppl;
    string msg;

    try
    {
        checkAppl.setupFromCommandLine(argc, argv);
        checkAppl.configure();
        checkAppl.identifyDaemon(); // includes: getSupportedMibs();
        checkAppl.createMessages();

        /* nothing to prove, finding an appropriate daemon is enough for here */

        rc = STATE_OK;
    }
    catch(alarm_timeout_reached &a)
    {
        rc = STATE_CRITICAL;
        msg = string(a.what()) + " (supposably daemon not running)";
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
