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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_APPL_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_APPL_H_INCLUDED__

#include <smart-snmpd-nagios-plugins/snmp-comm.h>
#include <smart-snmpd-nagios-plugins/nagios-stats.h>
#include <smart-snmpd-nagios-plugins/snmp-daemon-identifiers.h>
#include <smart-snmpd-nagios-plugins/snmp-appl.h>

#undef loggerModuleName
#define loggerModuleName "nagiosplugins.checkappl"

/**
 * exception to be thrown in case of unknown snmpd-type
 */
class alarm_timeout_reached
    : public std::runtime_error
{
public:
    //! default constructor
    alarm_timeout_reached()
        : runtime_error("Alarm timeout reached")
    {}

    //! destructor
    virtual ~alarm_timeout_reached() throw() {}
};

extern "C"
{
static void
alarm_handler(int signo)
{
    if( SIGALRM == signo )
    {
        throw alarm_timeout_reached();
    }
}
}

/**
 * class to fetch statically addressable objects from an snmpd
 */
class FetchStaticObjects
    : public SnmpAppl
{
protected:
    typedef SupportedMibData SupportedMibDataType;

public:
    //! default constructor
    FetchStaticObjects()
        : SnmpAppl()
        , mFetchedData()
    {}

    /**
     * adds the supported check options to the given options_description instance
     *
     * This method introduces the signature to add check options. Check options
     * are usually options to specify eg. warning or critical thresholds on the
     * one hand and allow fetched object specification on the other hand.
     * The latter one will be supported in derived objects whereby the first
     * category usually becomes delegated.
     *
     * @param checkopts - options_description instance to add the check options to
     */
    virtual void add_check_options(options_description &checkopts) const { (void)checkopts; }

    /**
     * returns the name of the identified daemon
     *
     * @return the name of the identified daemon
     */
    virtual string const & getDaemonName() const = 0;

    /**
     * fetch the data from snmpd
     *
     * @param mibData - the specification which data to fetch
     */
    void fetchData(SupportedMibData &mibData)
    {
        vector<Oid> const &dataOids = mibData.getDataOids();

        mFetchedData.assign( dataOids.begin(), dataOids.end() );
        if( SNMP_CLASS_SUCCESS != mSnmpComm.get( mFetchedData ) )
            throw snmp_bad_request( string( "Cannot fetch values to check from " ) + getDaemonName() );
    }

    /**
     *
     */
    vector<Vb> const & getFetchedData() const { return mFetchedData; }

protected:
    /**
     *
     */
    vector<Vb> mFetchedData;
};

class FetchTableObjects
    : public FetchStaticObjects
{
protected:
    typedef SupportedMibDataTable SupportedMibDataType;

    class GetBulkSearchMatchingRow
    {
    public:
        GetBulkSearchMatchingRow( vector<Oid> const &start, string const &nameRef )
            : mStart( start )
            , mNameRef( nameRef )
            , mFoundRowIndex( -1 )
        {}

        ~GetBulkSearchMatchingRow() {}

        bool operator () (vector<Vb> const &varBinds)
        {
            for( vector<Vb>::size_type i = 0; i < varBinds.size(); ++i )
            {
                Oid idxOid;
                varBinds[i].get_oid( idxOid );

                if( mStart[i].nCompare( mStart[i].len(), idxOid ) != 0 )
                {
                    // reached end of table, caller shall break here and now
                    return true;
                }

                if( mNameRef == varBinds[i].get_printable_value() )
                {
                    // save matching oid index component
                    mFoundRowIndex = idxOid[ idxOid.len() - 1 ];
                    // caller shall break here
                    return true;
                }
            }

            return false;
        }

        long getFoundRowIndex() const { return mFoundRowIndex; }

    protected:
        vector<Oid> const &mStart;
        string const &mNameRef;
        long mFoundRowIndex;

    private:
        GetBulkSearchMatchingRow();
    };

public:
    FetchTableObjects()
        : FetchStaticObjects()
        , mName()
    {}

    virtual void add_check_options(options_description &checkopts) const
    {
        checkopts.add_options()
            ("index,i", value<long>(), "table index of object to check")
            ("name,n", value<string>(), "name of the object to check")
            ;
    }

    virtual void validate_options() const
    {
        vector<const char *> v;
        v.push_back( "index" );
        v.push_back( "name" );
        option_required( mCmndlineValuesMap, v );
    }

    virtual void configure()
    {
        SnmpAppl::configure();

        mName = mCmndlineValuesMap["name"].as<string>();
    }

    void fetchData(SupportedMibDataTable &mibData)
    {
        if( mCmndlineValuesMap.count("index") && !mCmndlineValuesMap["index"].defaulted() )
        {
            mibData.setFoundRowIndex( mCmndlineValuesMap["index"].as<long>() );
            FetchStaticObjects::fetchData(mibData);
        }
        else
        {
            vector<Oid> const & nameSearchOids( mibData.getRowSearchColumnOids() );

            GetBulkSearchMatchingRow searchMatchingRow( nameSearchOids, mName );

            if( SNMP_CLASS_SUCCESS != mSnmpComm.get_table( nameSearchOids, searchMatchingRow ) )
                throw snmp_bad_request( string( "Cannot fetch values to search for '" ) + mName + "' from " + getDaemonName() );
            if( -1 == searchMatchingRow.getFoundRowIndex() )
                throw snmp_bad_result( string( "Cannot find row matching '" ) + mName + "' from " + getDaemonName() );

            mibData.setFoundRowIndex( searchMatchingRow.getFoundRowIndex() );
            FetchStaticObjects::fetchData(mibData);
        }
    }

protected:
    string mName;
};

/**
 * check application - handles the rough application tasks around SnmpCheck instances
 *
 * This class defines an application for usual checks against snmp daemons.
 *
 * @param ShowPerformanceData - show performance data or not (default true)
 */
template< class Fetch, class Check, bool ShowPerformanceData = true >
class CheckPluginAppl
    : public Fetch
    , public Check
{
protected:
    typedef CheckPluginAppl< Fetch, Check, ShowPerformanceData > PluginApplType;
    typedef SupportedMibData::DataMapType DataMapType;
    typedef typename Check::CheckType DataMappedCheckType;
    typedef typename Fetch::SupportedMibDataType SupportedMibDataType;

public:
    /**
     * constructs application object
     */
    CheckPluginAppl()
        : Fetch()
        , Check()
        , mReported(false)
        , mSupportedSnmpDaemons()
        , mIdentifiedSnmpDaemon( mSupportedSnmpDaemons.end() )
        , mSupportedMibData(0)
        , mResultMessage()
        , mPerformanceMessage()
        , mDataMap()
    {}

    /**
     * destructs application objects
     */
    virtual ~CheckPluginAppl() {}

    virtual void initSupportedSnmpDaemons() = 0;

    virtual SupportedMibDataType * getMibData( SnmpDaemonIdentifier const &identifiedDaemon ) = 0;

    virtual void setupFromCommandLine(int argc, char *argv[])
    {
        initSupportedSnmpDaemons();
        Fetch::setupFromCommandLine(argc, argv);
    }

    vector<SnmpDaemonIdentifier> & getSupportedSnmpDaemons()
    {
        if( mSupportedSnmpDaemons.empty() )
            initSupportedSnmpDaemons();
        if( mSupportedSnmpDaemons.empty() )
            throw std::runtime_error( "No supported SNMP daemons" );
        return mSupportedSnmpDaemons;
    }

    vector<SnmpDaemonIdentifier> const & getSupportedSnmpDaemons() const
    {
        if( mSupportedSnmpDaemons.empty() )
            throw std::runtime_error( "No supported SNMP daemons" );
        return mSupportedSnmpDaemons;
    }

    virtual void add_general_options(options_description &generalopts) const
    {
        Fetch::add_general_options(generalopts);
        generalopts.add_options()
            ("alarm-timeout,a", value<unsigned>()->default_value(45), "sets alarm timeout in seconds")
            ("show-performance-data", value<bool>()->default_value(ShowPerformanceData), "enable or disable output of nagios performance data")
            ;
    }

    virtual void add_check_options(options_description &checkopts) const
    {
        string snmpDaemons;
        vector<SnmpDaemonIdentifier> const &supportedSnmpDaemons = getSupportedSnmpDaemons();
        for( typename vector<SnmpDaemonIdentifier>::const_iterator ci = supportedSnmpDaemons.begin();
             ci != supportedSnmpDaemons.end();
             ++ci )
        {
            if( snmpDaemons.empty() )
            {
                snmpDaemons = "name of the snmpd type to query: ";
            }
            else
            {
                snmpDaemons += ", ";
            }
            snmpDaemons += ci->getName();
        }

        checkopts.add_options()
            ("snmpd-type,s", value<string>()->default_value("auto"), snmpDaemons.c_str())
            ;

        Check::add_check_options(checkopts);
        Fetch::add_check_options(checkopts);
    }

    /**
     * initializes program options and return them
     *
     * @return options_description - the common program options
     */
    virtual options_description get_options() const
    {
        options_description checkopts("Check options");
        add_check_options( checkopts );

        // Declare an options description instance which will include
        // all the options
        options_description all = Fetch::get_options();
        all.add(checkopts);

        return all;
    }

    virtual void validate_options() const
    {
        Fetch::validate_options();
        variables_map const &vm = this->mCmndlineValuesMap;
        Check::validate_options( vm );

        if( ( 0 != vm.count("snmpd-type") ) && !vm["snmpd-type"].defaulted() )
        {
            string snmpdType = vm["snmpd-type"].as<string>();
            vector<SnmpDaemonIdentifier> const &supportedSnmpDaemons = getSupportedSnmpDaemons();
            bool found = false;

            for( typename vector<SnmpDaemonIdentifier>::const_iterator ci = supportedSnmpDaemons.begin();
                 ci != supportedSnmpDaemons.end();
                 ++ci )
            {
                if( ci->getName() == snmpdType )
                {
                    found = true;
                    break;
                }
            }

            if( !found )
            {
                validation_error e(validation_error::invalid_option_value, snmpdType, "snmpd-type");
                throw e;
            }
        }
    }

    /**
     * configures application
     */
    void configure()
    {
        Fetch::configure();

        variables_map const &vm = this->mCmndlineValuesMap;
        Check::configure( vm );

        if( ( vm.count("alarm-timeout") != 0 ) && ( 0 != vm["alarm-timeout"].as<unsigned>() ) )
        {
            signal( SIGALRM, alarm_handler );
            alarm( vm["alarm-timeout"].as<unsigned>() );
        }
    }

    bool reported() const { return mReported; }

    int report(int rc, string const &msg)
    {
        if( !mReported )
        {
            variables_map const &vm = this->mCmndlineValuesMap;
            if( ( vm.count("alarm-timeout") != 0 ) && ( 0 != vm["alarm-timeout"].as<unsigned>() ) )
            {
                alarm( 0 );
            }

            cout << getCheckName() << " " << (((int)(lengthof(states))) > rc ? states[rc] : "UNKNOWN");
            if( msg.empty() )
            {
                if( !getResultMessage().empty() )
                    cout << " - " << getResultMessage();
                if( vm["show-performance-data"].as<bool>() && !getPerformanceMessage().empty() )
                    cout << "|" << getPerformanceMessage();
                cout << endl;
            }
            else
            {
                cout << " - " << msg << endl;
            }

            mReported = true;
        }

        return rc;
    }

    using Fetch::fetchData;

    virtual void fetchData()
    {
        LOG_BEGIN( loggerModuleName, EVENT_LOG | 1 );
        LOG( "fetching data" );
        LOG_END;

        if( NULL == mSupportedMibData )
            throw( runtime_error( "out of order execution of SnmpCheckAppl::fetchData()" ) );
        fetchData(*mSupportedMibData);
    }

    virtual void convert()
    {
        LOG_BEGIN( loggerModuleName, EVENT_LOG | 1 );
        LOG( "normalizing and converting fetched data" );
        LOG_END;

        if( NULL == mSupportedMibData )
            throw( runtime_error( "out of order execution of SnmpCheckAppl::convert()" ) );

        mDataMap.clear();
        mSupportedMibData->convertSnmpData( this->mFetchedData, mDataMap );
    }

    /**
     * verifies that the daemon we talk to is the daemon we want to talk to
     *
     * This method requests the value of the oid to identify the daemon
     * as described in the mib-ident and compares the result against the
     * expected value. If the result and the expected result are equal
     * in the full length of the expected result (the received result
     * might be longer), the daemon is estimated identified.
     *
     * @param mi - the SnmpDaemonIdentifier instance describing the wanted daemon
     *
     * @return bool - true if it's the wanted one, false otherwise
     *
     * @see MibIdent
     */
    bool verifyDaemon( SnmpDaemonIdentifier const &mi )
    {
        Oid oid(mi.getProveOid());
        Vb vb(oid);

        if( SNMP_CLASS_SUCCESS == this->mSnmpComm.get( vb ) )
        {
            if( ( vb.get_syntax() == sNMP_SYNTAX_NOSUCHINSTANCE ) ||
                ( vb.get_syntax() == sNMP_SYNTAX_NOSUCHOBJECT ) )
            {
                return false;
            }

            string s = vb.get_printable_value();
            if( 0 == s.find( mi.getProveValue() ) ) // must start with ...
            {
                return true;
            }
        }

        return false;
    }

    /**
     * identifies mib region to use - either take specified by user or try to detect
     *
     * @param vm - map of values specified on command line
     *
     * @see MibIdent
     */
    virtual void identifyDaemon()
    {
        vector<SnmpDaemonIdentifier> &supportedSnmpDaemons = getSupportedSnmpDaemons();
        variables_map const &vm = this->mCmndlineValuesMap;

        if( ( 0 == vm.count("snmpd-type") ) || vm["snmpd-type"].defaulted() )
        {
            if( this->mSnmpComm.can_combine_requests() )
            {
                vector<Vb> daemonIdentifyVarBinds;
                for( mIdentifiedSnmpDaemon = supportedSnmpDaemons.begin();
                     mIdentifiedSnmpDaemon != supportedSnmpDaemons.end();
                     ++mIdentifiedSnmpDaemon )
                {
                    /*
                    if( verifyDaemon( *mIdentifiedSnmpDaemon ) )
                        break;
                    */
                    daemonIdentifyVarBinds.push_back( mIdentifiedSnmpDaemon->getProveOid() );
                }

                int rc = this->mSnmpComm.get( daemonIdentifyVarBinds );
                if( SNMP_CLASS_SUCCESS == rc )
                {
                    typename vector<Vb>::iterator vblistIterator;

                    for( mIdentifiedSnmpDaemon = supportedSnmpDaemons.begin(), vblistIterator = daemonIdentifyVarBinds.begin();
                         ( mIdentifiedSnmpDaemon != supportedSnmpDaemons.end() ) && ( vblistIterator != daemonIdentifyVarBinds.end() );
                         ++mIdentifiedSnmpDaemon, ++vblistIterator )
                    {
                        if( ( vblistIterator->get_syntax() == sNMP_SYNTAX_NOSUCHINSTANCE ) ||
                            ( vblistIterator->get_syntax() == sNMP_SYNTAX_NOSUCHOBJECT ) )
                        {
                            continue;
                        }

                        string s = vblistIterator->get_printable_value();
                        if( 0 == s.find( mIdentifiedSnmpDaemon->getProveValue() ) ) // must start with ...
                        {
                            break;
                        }
                    }
                }
            }
            else
            {
                for( mIdentifiedSnmpDaemon = supportedSnmpDaemons.begin();
                     mIdentifiedSnmpDaemon != supportedSnmpDaemons.end();
                     ++mIdentifiedSnmpDaemon )
                {
                    if( verifyDaemon( *mIdentifiedSnmpDaemon ) )
                        break;
                }
            }
        }
        else
        {
            string const &s = vm["snmpd-type"].as<string>();
            for( mIdentifiedSnmpDaemon = supportedSnmpDaemons.begin();
                 mIdentifiedSnmpDaemon != supportedSnmpDaemons.end();
                 ++mIdentifiedSnmpDaemon )
            {
                if( 0 == s.find( mIdentifiedSnmpDaemon->getName() ) && verifyDaemon( *mIdentifiedSnmpDaemon ) )
                    break;
            }
        }

        if( mIdentifiedSnmpDaemon != supportedSnmpDaemons.end() )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 5 );
            LOG( string( string("Using SNMP daemon type ") + mIdentifiedSnmpDaemon->getName() ).c_str() );
            LOG_END;

            if( NULL == ( mSupportedMibData = getMibData( *mIdentifiedSnmpDaemon ) ) )
                throw unknown_daemon();
        }
        else
            throw unknown_daemon();
    }

    virtual string const & getDaemonName() const
    {
        if( mIdentifiedSnmpDaemon != mSupportedSnmpDaemons.end() )
            return mIdentifiedSnmpDaemon->getName();
        else
            throw unknown_daemon();
    }

    virtual string createResultMessage( DataMapType const &dataMap ) const = 0;
    virtual string createPerformanceMessage( DataMapType const &dataMap ) const = 0;

    void createMessages()
    {
        LOG_BEGIN( loggerModuleName, EVENT_LOG | 1 );
        LOG( "creating result messages" );
        LOG_END;

        setResultMessage( createResultMessage( mDataMap ) );
        setPerformanceMessage( createPerformanceMessage( mDataMap ) );
    }

    string const & getResultMessage() const { return mResultMessage; }
    CheckPluginAppl const & setResultMessage( string const &resultMessage )
    {
        mResultMessage = resultMessage;
        return *this;
    }

    string const & getPerformanceMessage() const { return mPerformanceMessage; }
    CheckPluginAppl const & setPerformanceMessage( string const &performanceMessage )
    {
        mPerformanceMessage = performanceMessage;
        return *this;
    }

    template < class Cmp >
    int prove( Cmp const &cmp = Cmp() ) const
    {
        LOG_BEGIN( loggerModuleName, EVENT_LOG | 1 );
        LOG( "proving values" );
        LOG_END;

        DataMappedCheckType const &val = mDataMap[ProveValueMapKey].as<DataMappedCheckType>();
        return Check::prove( val, cmp );
    }

protected:
    /**
     * already reported?
     */
    bool mReported;
    /**
     * supported snmp daemons
     */
    vector<SnmpDaemonIdentifier> mSupportedSnmpDaemons;
    /**
     *
     */
    typename vector<SnmpDaemonIdentifier>::iterator mIdentifiedSnmpDaemon;
    /**
     *
     */
    SupportedMibDataType *mSupportedMibData;
    /**
     * result message
     */
    string mResultMessage;
    /**
     * performance message
     */
    string mPerformanceMessage;
    /**
     *
     */
    DataMapType mDataMap;

    virtual string const getCheckName() const = 0;

private:
    /**
     * forbidden copy constructor - we can only have one application
     */
    CheckPluginAppl(CheckPluginAppl const &);
    /**
     * forbidden assignment operator
     */
    CheckPluginAppl & operator = (CheckPluginAppl const &);
};

#undef loggerModuleName

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_APPL_H_INCLUDED__ */
