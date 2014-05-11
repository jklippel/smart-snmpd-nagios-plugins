/*
 * Copyright 2010,2011 Matthias Haag, Jens Rehsack, Volker Hein
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

#include <boost/regex.hpp>

class ProcessTuple
    : public boost::tuple<string, string, string, string, string>
{
public:
    ProcessTuple( string const &args = "", string const &user = "", string const &group = "",
                  string const &effectiveUser = "", string const &effectiveGroup = "" )
        : boost::tuple<string, string, string, string, string>( args, user, group, effectiveUser, effectiveGroup )
    {}

    bool hasArguments()          const { return !get<0>().empty(); }
    bool hasUsername()           const { return !get<1>().empty(); }
    bool hasGroupname()          const { return !get<2>().empty(); }
    bool hasEffectiveUsername()  const { return !get<3>().empty(); }
    bool hasEffectiveGroupname() const { return !get<4>().empty(); }

    string const & getArguments()            const { return get<0>(); }
    string const & getUsername()             const { return get<1>(); }
    string const & getGroupname()            const { return get<2>(); }
    string const & getEffectiveUsername()    const { return get<3>(); }
    string const & getEffectiveGroupname()   const { return get<4>(); }

    ProcessTuple & setArguments( string const &args )           { get<0>() = args;  return *this; }
    ProcessTuple & setUsername( string const &user )            { get<1>() = user;  return *this; }
    ProcessTuple & setGroupname( string const &group )          { get<2>() = group; return *this; }
    ProcessTuple & setEffectiveUsername( string const &user )   { get<3>() = user;  return *this; }
    ProcessTuple & setEffectiveGroupname( string const &group ) { get<4>() = group; return *this; }
};

class ProcessCompareTuple
    : public boost::tuple<string, string, string, string, string, string>
{
public:
    ProcessCompareTuple( string const &command = "", string const &arg = "", string const &user = "", string const &group = "",
                         string const &effectiveUser = "", string const &effectiveGroup = "" )
        : boost::tuple<string, string, string, string, string, string>( command, arg, user, group, effectiveUser, effectiveGroup )
        // argument has to be between whitespace and ( whitespace / end-of-line )
        //
        , mArgumentRegex( ".*\\s+" + arg + "(\\s+.*|$)" )
        // command has to be between begin-of-line and ( whitespace / end-of-line )
        //
        , mCommandRegex( "^" + command + "(\\s+.*|$)" )
    {}

    bool hasCommand()            const { return !get<0>().empty(); }
    bool hasArgument()           const { return !get<1>().empty(); }
    bool hasUsername()           const { return !get<2>().empty(); }
    bool hasGroupname()          const { return !get<3>().empty(); }
    bool hasEffectiveUsername()  const { return !get<4>().empty(); }
    bool hasEffectiveGroupname() const { return !get<5>().empty(); }

    string const & getCommand()             const { return get<0>(); }
    string const & getArgument()            const { return get<1>(); }
    string const & getUsername()            const { return get<2>(); }
    string const & getGroupname()           const { return get<3>(); }
    string const & getEffectiveUsername()   const { return get<4>(); }
    string const & getEffectiveGroupname()  const { return get<5>(); }

    ProcessCompareTuple & setCommand( string const &command )           { get<0>() = command; return *this; }
    ProcessCompareTuple & setArgument( string const &arg )              { get<1>() = arg;     return *this; }
    ProcessCompareTuple & setUsername( string const &user )             { get<2>() = user;    return *this; }
    ProcessCompareTuple & setGroupname( string const &group )           { get<3>() = group;   return *this; }
    ProcessCompareTuple & setEffectiveUsername( string const &user )    { get<4>() = user;    return *this; }
    ProcessCompareTuple & setEffectiveGroupname( string const &group )  { get<5>() = group;   return *this; }

    bool checkCommand( string const &args ) const
    {
        if ( ! hasCommand() )
        {
            // always return true if no command is given
            //
            return true;
        }

        return boost::regex_match( args, mCommandRegex );
    }

    bool checkArgument( string const &args ) const
    {
        if ( ! hasArgument() )
        {
            // always return true if no argument is given
            //
            return true;
        }

        return boost::regex_match( args, mArgumentRegex );
    }

    bool checkUsername( string const &username ) const
    {
        if ( ! hasUsername() )
        {
            // always return true if no username is given
            //
            return true;
        }

        return username.compare( getUsername() ) == 0;
    }

    bool checkGroupname( string const &groupname ) const
    {
        if ( ! hasGroupname() )
        {
            // always return true if no groupname is given
            //
            return true;
        }

        return groupname.compare( getGroupname() ) == 0;
    }

    bool checkEffectiveUsername( string const &username ) const
    {
        if ( ! hasEffectiveUsername() )
        {
            // always return true if no username is given
            //
            return true;
        }

        return username.compare( getEffectiveUsername() ) == 0;
    }

    bool checkEffectiveGroupname( string const &groupname ) const
    {
        if ( ! hasEffectiveGroupname() )
        {
            // always return true if no groupname is given
            //
            return true;
        }

        return groupname.compare( getEffectiveGroupname() ) == 0;
    }

protected:
    boost::regex mArgumentRegex;
    boost::regex mCommandRegex;
};

std::string
to_string(ProcessCompareTuple const &t)
{
    string s;

    if ( t.hasCommand() )
        s += "command=" + t.getCommand() + ",";
    if ( t.hasArgument() )
        s += "arg=" + t.getArgument() + ",";
    if ( t.hasUsername() )
        s += "username=" + t.getUsername() + ",";
    if ( t.hasGroupname() )
        s += "groupname=" + t.getGroupname() + ",";
    if ( t.hasEffectiveUsername() )
        s += "eff_username=" + t.getEffectiveUsername() + ",";
    if ( t.hasEffectiveGroupname() )
        s += "eff_groupname=" + t.getEffectiveGroupname();

    if ( s[ s.length() - 1 ] == ',' )
        s.erase( s.length() - 1 );

    return s;
}

class ProcessMap
    : public std::map<long, ProcessTuple>
{
protected:
    typedef std::map<long, ProcessTuple> MapType;

public:
    MapType::iterator
    addOrUpdateArgs( long key, string const &args )
    {
        MapType::iterator lb = lower_bound(key);

        if ( lb != end() && !( key_comp()( key, lb->first )))
        {
            lb->second.setArguments( args );
            return lb;
        }
        else
        {
            typedef MapType::value_type MVT;

            ProcessTuple pt( args );
            return insert( lb, MVT( key, pt ) );
        }
    }

    MapType::iterator
    addOrUpdateUsername( long key, string const &username )
    {
        MapType::iterator lb = lower_bound(key);

        if ( lb != end() && !( key_comp()( key, lb->first )))
        {
            lb->second.setUsername( username );
            return lb;
        }
        else
        {
            typedef MapType::value_type MVT;

            ProcessTuple pt( "", username );
            return insert( lb, MVT( key, pt ) );
        }
    }

    MapType::iterator
    addOrUpdateGroupname( long key, string const &groupname )
    {
        MapType::iterator lb = lower_bound(key);

        if ( lb != end() && !( key_comp()( key, lb->first )))
        {
            lb->second.setGroupname( groupname );
            return lb;
        }
        else
        {
            typedef MapType::value_type MVT;

            ProcessTuple pt( "", "", groupname );
            return insert( lb, MVT( key, pt ) );
        }
    }

    MapType::iterator
    addOrUpdateEffectiveUsername( long key, string const &username )
    {
        MapType::iterator lb = lower_bound(key);

        if ( lb != end() && !( key_comp()( key, lb->first )))
        {
            lb->second.setEffectiveUsername( username );
            return lb;
        }
        else
        {
            typedef MapType::value_type MVT;

            ProcessTuple pt( "", "", "", username );
            return insert( lb, MVT( key, pt ) );
        }
    }

    MapType::iterator
    addOrUpdateEffectiveGroupname( long key, string const &groupname )
    {
        MapType::iterator lb = lower_bound(key);

        if ( lb != end() && !( key_comp()( key, lb->first )))
        {
            lb->second.setEffectiveGroupname( groupname );
            return lb;
        }
        else
        {
            typedef MapType::value_type MVT;

            ProcessTuple pt( "", "", "", "", groupname );
            return insert( lb, MVT( key, pt ) );
        }
    }
};

class SmartSnmpdProcessesMibData
{
public:
    typedef AnyDataMap DataMapType;

    SmartSnmpdProcessesMibData() {}

    virtual ~SmartSnmpdProcessesMibData() {}

    virtual void convertSnmpData( ProcessMap &processMap, DataMapType &dataMap )
    {
        // just push the length of the process map as prove value
        //
        AbsoluteThreshold count( processMap.size() );

        dataMap.insert( make_pair( ProveValueMapKey, RangeThreshold<AbsoluteThreshold>( count, count ) ) );
        dataMap.insert( make_pair( "count", count ) );
    }
};

class GetBulkProcesses
{
public:
    GetBulkProcesses( ProcessCompareTuple const &aProcessComperatorTuple, ProcessMap &result_buf )
        : mStart( SM_PROCESS_ENTRY )
        , mResultBuf( result_buf )
        , mProcessCompare( aProcessComperatorTuple )
    {}

    ~GetBulkProcesses() {}

    bool operator () (vector<Vb> const &varBinds)
    {
        // OIDs should come in the following order:
        //
        //    SM_PROCESS_ARGS
        //    SM_PROCESS_USERNAME
        //    SM_PROCESS_GROUPNAME
        //    SM_PROCESS_EFFECTIVE_USERNAME
        //    SM_PROCESS_EFFECTIVE_GROUPNAME
        //
//        cout << "BULKING" << endl;

        Oid idxOid;
        long lineIdx;

        string arguments, username, groupname, effectiveUsername, effectiveGroupname;

        SnmpComm::extract_value( varBinds[ 0 ], arguments );
        SnmpComm::extract_value( varBinds[ 1 ], username );
        SnmpComm::extract_value( varBinds[ 2 ], groupname );
        SnmpComm::extract_value( varBinds[ 3 ], effectiveUsername );
        SnmpComm::extract_value( varBinds[ 4 ], effectiveGroupname );

        // check if values match the given filter
        //
        if ( mProcessCompare.checkCommand( arguments )
          && mProcessCompare.checkArgument( arguments )
          && mProcessCompare.checkUsername( username )
          && mProcessCompare.checkGroupname( groupname )
          && mProcessCompare.checkEffectiveUsername( effectiveUsername )
          && mProcessCompare.checkEffectiveGroupname( effectiveGroupname )
        )
        {
            varBinds[ 0 ].get_oid( idxOid );
            lineIdx = idxOid[ idxOid.len() - 1 ];

            mResultBuf.insert( make_pair( lineIdx,
                    ProcessTuple( arguments, username, groupname, effectiveUsername, effectiveGroupname ) ) );
        }
        return false;
    }

protected:
    Oid const mStart;
    ProcessMap &mResultBuf;
    ProcessCompareTuple const &mProcessCompare;

private:
    GetBulkProcesses();
};

class FetchProcessObjects
    : public FetchStaticObjects
{
protected:
    typedef SmartSnmpdProcessesMibData SupportedMibDataType ;

public:
    FetchProcessObjects()
        : FetchStaticObjects()
        , mProcessCompare()
        , mFetchedData()
    {}

    virtual void add_check_options(options_description &checkopts) const
    {
        checkopts.add_options()
            ("process-command,P", value<string>(), "command of the process to check")
            ("process-argument,A", value<string>(), "argument of the process to check")
            ("process-username,u", value<string>(), "username of the process to check")
            ("process-groupname,g", value<string>(), "groupname of the process to check")
            ("process-effective-username,U", value<string>(), "effective username of the process to check")
            ("process-effective-groupname,G", value<string>(), "effective groupname of the process to check")
            ;
    }

    virtual void validate_options() const
    {
        vector<const char *> v;
        v.push_back( "process-command" );
        v.push_back( "process-argument" );
        v.push_back( "process-username" );
        v.push_back( "process-groupname" );
        v.push_back( "process-effective-username" );
        v.push_back( "process-effective-groupname" );
        option_required( mCmndlineValuesMap, v );
    }

    virtual void configure()
    {
        SnmpAppl::configure();

        string command, argument, username, groupname, effectiveUsername, effectiveGroupname;

        if ( mCmndlineValuesMap.count("process-command") )
        {
            command = mCmndlineValuesMap["process-command"].as<string>();
        }
        if ( mCmndlineValuesMap.count("process-argument") )
        {
            argument = mCmndlineValuesMap["process-argument"].as<string>();
        }
        if ( mCmndlineValuesMap.count("process-username") )
        {
            username = mCmndlineValuesMap["process-username"].as<string>();
        }
        if ( mCmndlineValuesMap.count("process-groupname") )
        {
            groupname = mCmndlineValuesMap["process-groupname"].as<string>();
        }
        if ( mCmndlineValuesMap.count("process-effective-username") )
        {
            effectiveUsername = mCmndlineValuesMap["process-effective-username"].as<string>();
        }
        if ( mCmndlineValuesMap.count("process-effective-groupname") )
        {
            effectiveGroupname = mCmndlineValuesMap["process-effective-groupname"].as<string>();
        }

        mProcessCompare = ProcessCompareTuple( command, argument, username, groupname, effectiveUsername, effectiveGroupname );
    }

    void fetchData(SmartSnmpdProcessesMibData &mibData)
    {
        (void)mibData;
        GetBulkProcesses searchMatchingRow( mProcessCompare, mFetchedData );

        vector<Oid> procOids;
        procOids.push_back( SM_PROCESS_ARGS );
        procOids.push_back( SM_PROCESS_USERNAME );
        procOids.push_back( SM_PROCESS_GROUPNAME );
        procOids.push_back( SM_PROCESS_EFFECTIVE_USERNAME );
        procOids.push_back( SM_PROCESS_EFFECTIVE_GROUPNAME );

        if( SNMP_CLASS_SUCCESS != mSnmpComm.get_table( procOids, searchMatchingRow ) )
            throw snmp_bad_request( string( "Cannot fetch values to search from " + getDaemonName() ) );
    }

    ProcessMap const & getFetchedData() const { return mFetchedData; }

protected:
    ProcessCompareTuple mProcessCompare;
    ProcessMap mFetchedData;
};

class SnmpProcsCheckAppl
    : public CheckPluginAppl< FetchProcessObjects, SnmpWarnCritCheck< RangeThreshold<AbsoluteThreshold> >, false >
{
public:
    SnmpProcsCheckAppl()
        : CheckPluginAppl< FetchProcessObjects, SnmpWarnCritCheck< RangeThreshold<AbsoluteThreshold> >, false >()
    {}

    virtual ~SnmpProcsCheckAppl() {}

    virtual void initSupportedSnmpDaemons()
    {
        mSupportedSnmpDaemons.push_back( IdentifySmartSnmpdMib );
    }

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon )
    {
        if( identifiedDaemon.getName() == IdentifySmartSnmpdMib.getName() )
        {
            return new SmartSnmpdProcessesMibData();
        }

        throw unknown_daemon();
    }

    string createResultMessage( DataMapType const &dataMap ) const
    {
        AbsoluteThreshold count = dataMap["count"].as<AbsoluteThreshold>();

        string summary = "( " + to_string( mProcessCompare ) + " )";

        string msg = string( to_string( count ) + " Processes " + summary );

        return msg;
    }

    string createPerformanceMessage( DataMapType const &dataMap ) const
    {
        AbsoluteThreshold count = dataMap["count"].as<AbsoluteThreshold>();
        return string("count=" + to_string( count ) );
    }

protected:
    virtual string const getCheckName() const { return "PROCS_EXT"; }
    /**
     * contains the application name
     */
    virtual string const getApplName() const { return "check_procs_by_snmp"; }
    /**
     * contains the application version
     */
    virtual string const getApplVersion() const { return SSNC_VERSION_STRING; }
    /**
     * short description of the application
     */
    virtual string const getApplDescription() const { return "Check count of a certain running process via Simple Network Management Protocol"; }
};

int main(int argc, char *argv[])
{
    int rc = STATE_EXCEPTION;
    SnmpProcsCheckAppl checkAppl;
    string msg;


//    string s;
//
//    while ( s != "quit" )
//    {
//        cin >> s;
//
//        boost::regex re;
//
//        try
//        {
//            re.assign( ".*aaa.*\\d+", boost::regex_constants::icase );
//        }
//        catch( boost::regex_error &e )
//        {
//            cout << "error" << endl;
//            continue;
//        }
//
//        if ( boost::regex_match( s, re ) )
//        {
//            cout << "MATCH" << endl;
//        }
//    }
//
//    return 0;

    try
    {
        checkAppl.setupFromCommandLine(argc, argv);
        checkAppl.configure();
        checkAppl.identifyDaemon(); // includes: getSupportedMibs();

        checkAppl.fetchData();
        checkAppl.convert();

        checkAppl.createMessages();
        rc = checkAppl.prove< RangeCmp<AbsoluteThreshold> >();
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
