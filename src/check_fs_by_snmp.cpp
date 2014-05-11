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
#include <smart-snmpd-nagios-plugins/snmp-comm.h>
#include <smart-snmpd-nagios-plugins/snmp-check.h>
#include <smart-snmpd-nagios-plugins/snmp-check-types.h>
#include <smart-snmpd-nagios-plugins/snmp-check-appl.h>

class FilesystemMibData
    : public SupportedMibDataTable
{
public:
    FilesystemMibData( vector<Oid> const &dataOids, vector<Oid> const &rowSearchColumnOids )
        : SupportedMibDataTable( dataOids, rowSearchColumnOids )
    {}

    virtual ~FilesystemMibData() {}

    FilesystemMibData & setStorageData( unsigned long long used, unsigned long long total, DataMapType &dataMap )
    {
        if( 0 == total )
        {
            used = 0;
            total = 1;
        }
        SizeThreshold storage( BytesThreshold(total - used), RelativeThreshold( ((double)used / (double)total) ) );

        dataMap.insert( make_pair( ProveValueMapKey, storage ) );
        dataMap.insert( make_pair( "used", used ) );
        dataMap.insert( make_pair( "total", total ) );

        return *this;
    }
};

static const Oid SmFilesystemDataOids[] = { SM_FILE_SYSTEM_MOUNTPOINT, SM_FILE_SYSTEM_TOTAL, SM_FILE_SYSTEM_USED };
static const Oid SmFilesystemSearchOids[] = { SM_FILE_SYSTEM_DEVICE, SM_FILE_SYSTEM_MOUNTPOINT };
class SmartSnmpdFileSystemMibData
    : public FilesystemMibData
{
public:
    SmartSnmpdFileSystemMibData()
        : FilesystemMibData( make_vector<Oid, lengthof(SmFilesystemDataOids)>( SmFilesystemDataOids ),
                             make_vector<Oid, lengthof(SmFilesystemSearchOids)>( SmFilesystemSearchOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        string mnt;
        unsigned long long total, used;
        if( SnmpComm::extract_value( vblist[0], mnt ) &&
            SnmpComm::extract_value( vblist[1], total ) &&
            SnmpComm::extract_value( vblist[2], used ) )
        {
            setStorageData( used, total, dataMap );
            dataMap.insert( make_pair( "mnt", mnt ) );
        }
        else
        {
            throw snmp_bad_result( "File system data incomplete or corrupt" );
        }
    }
};

static const Oid HrStorageDataOids[] = { HR_STORAGE_DESCR, HR_STORAGE_ALLOC_UNITS, HR_STORAGE_SIZE, HR_STORAGE_USED };
static const Oid HrStorageSearchOids[] = { HR_STORAGE_DESCR };
class HostResourcesFileSystemMibData
    : public FilesystemMibData
{
public:
    HostResourcesFileSystemMibData()
        : FilesystemMibData( make_vector<Oid, lengthof(HrStorageDataOids)>( HrStorageDataOids ),
                             make_vector<Oid, lengthof(HrStorageSearchOids)>( HrStorageSearchOids ) )
    {}

    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap )
    {
        string mnt;
        unsigned long long bs, total, used;
        if( SnmpComm::extract_value( vblist[0], mnt ) &&
            SnmpComm::extract_value( vblist[1], bs ) &&
            SnmpComm::extract_value( vblist[2], total ) &&
            SnmpComm::extract_value( vblist[3], used ) )
        {
            used *= bs;
            total *= bs;

            setStorageData( used, total, dataMap );
            dataMap.insert( make_pair( "mnt", mnt ) );
        }
        else
        {
            throw snmp_bad_result( "File system data incomplete or corrupt" );
        }
    }
};

class SnmpFsCheckAppl
    : public CheckPluginAppl< FetchTableObjects, SnmpMandatoryWarnCritCheck< SizeThreshold > >
{
public:
    SnmpFsCheckAppl()
        : CheckPluginAppl< FetchTableObjects, SnmpMandatoryWarnCritCheck< SizeThreshold > >()
    {}

    virtual ~SnmpFsCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
        mSupportedSnmpDaemons.push_back( IdentifyNetSnmpd );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
        {
            return new SmartSnmpdFileSystemMibData();
        }
        else if( identifiedDaemon.getName() == IdentifyNetSnmpd.getName() )
        {
            return new HostResourcesFileSystemMibData();
        }

        throw unknown_daemon();
    }

    string createResultMessage( DataMapType const &dataMap ) const
    {
        unsigned long long mb = 1024ULL * 1024;
        unsigned long long total = dataMap["total"].as<unsigned long long>();
        unsigned long long used = dataMap["used"].as<unsigned long long>();
        string const &mnt = dataMap["mnt"].as<string>();

        double d = 0 == total ? 100.0 : ((double)used * 100) / total;
        unsigned long long used_percent = (unsigned long long)(d + 0.5);

        string msg = string("free space: ") +  mnt + " " + to_string( (total - used) / mb) + " MB"
                   + " (Usage: " + to_string(used_percent) + "%)";

        return msg;
    }

    string createPerformanceMessage( DataMapType const &dataMap ) const
    {
        SizeThreshold const &warn = getWarn();
        SizeThreshold const &crit = getCrit();

        unsigned long long total = dataMap["total"].as<unsigned long long>();
        unsigned long long used = dataMap["used"].as<unsigned long long>();
        unsigned long long checkWarning = warn.is_rel() ? (unsigned long long)( warn.relative() * total ) : (unsigned long long)(warn.absolute());
        unsigned long long checkCritical = crit.is_rel() ? (unsigned long long)( crit.relative() * total ) : (unsigned long long)(crit.absolute());
        unsigned long long mb = 1024ULL * 1024;
        string const &mnt = dataMap["mnt"].as<string>();

        checkWarning /= mb;
        checkCritical /= mb;

        string msg = mnt + "=" + to_string( used / mb ) + "MB;"
                   + to_string(checkWarning) + ";"
                   + to_string(checkCritical) + ";0;"
                   + to_string(total / mb);

        return msg;
    }

protected:
    virtual string const getCheckName() const { return "FILESYSTEM"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_fs_by_snmp"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check file system storage via Simple Network Management Protocol"; }
};

int
main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpFsCheckAppl checkAppl;
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
