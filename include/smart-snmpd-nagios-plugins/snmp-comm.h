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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_COMM_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_COMM_H_INCLUDED__

#include <smart-snmpd-nagios-plugins/snmp-pp-std.h>
#include <smart-snmpd-nagios-plugins/snmp-comm-types.h>
#include <smart-snmpd-nagios-plugins/program-options.h>

#include <boost/lexical_cast.hpp>

using namespace boost;

#include <string>
#include <iostream>
#include <iomanip>

using namespace std;

/**
 * internal used constant to define how many objects shall be
 * fetched with one bulk request by default
 */
static const int BulkMax = 16;

#undef loggerModuleName
#define loggerModuleName "nagiosplugins.snmpcomm"

/**
 * overloaded parser helper for snmp_version command line specification
 */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              snmp_version *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);

    try
    {
        v = any( str_to_snmp_version( s ) );
    }
    catch(out_of_range &e)
    {
        throw validation_error(validation_error::invalid_option_value);
    }
}

/**
 * overloaded parser helper for UdpAddress specification on command line
 */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              UdpAddress *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);

    UdpAddress addr( s.c_str() );
    if( !addr.valid() )
        throw validation_error(validation_error::invalid_option_value);
    v = any( addr );
}

class snmp_error
    : public std::runtime_error
{
public:
    snmp_error(string const &s)
        : std::runtime_error(s)
    {}

    virtual ~snmp_error() throw() {}

private:
    snmp_error();
};

/**
 * exception to be thrown in case of unknown mib-region
 */
class unknown_daemon
    : public snmp_error
{
public:
    unknown_daemon()
        : snmp_error("Unknown SNMP daemon (daemon not running or no supported MIB found)")
    {}

    virtual ~unknown_daemon() throw() {}
};

/**
 * exception to be thrown in case of bad snmp request
 */
class snmp_bad_request
    : public snmp_error
{
public:
    snmp_bad_request(string const &msg)
        : snmp_error(string("Bad snmp request: ") + msg)
    {}

    virtual ~snmp_bad_request() throw() {}
};

/**
 * exception to be thrown in case of bad snmp result
 */
class snmp_bad_result
    : public snmp_error
{
public:
    snmp_bad_result(string const &msg)
        : snmp_error(string("Bad snmp result: ") + msg)
    {}

    virtual ~snmp_bad_result() throw() {}
};

class GetBulkFetchHelper
{
public:
    GetBulkFetchHelper( Oid const &start, vector<Vb> &result_buf )
        : mStart( start )
        , mResultBuf( result_buf )
    {}

    ~GetBulkFetchHelper() {}

    bool operator () (Vb const &varBind)
    {
        Oid idxOid;
        varBind.get_oid( idxOid );
        if( mStart.nCompare( mStart.len(), idxOid ) != 0 )
            return true; // caller shall break here and now

        mResultBuf.push_back( varBind );

        return false;
    }
protected:
    Oid const mStart;
    vector<Vb> mResultBuf;

private:
    GetBulkFetchHelper();
};

class GetBulkFetchTableHelper
{
public:
    GetBulkFetchTableHelper( vector< vector<Vb> > &result_buf )
        : mResultBuf( result_buf )
    {}

    ~GetBulkFetchTableHelper() {}

    bool operator () (vector<Vb> const &varBind)
    {
        mResultBuf.push_back( varBind );

        return false;
    }

protected:
    vector< vector<Vb> > mResultBuf;

private:
    GetBulkFetchTableHelper();
};

/**
 * snmp communication helper class
 */
class SnmpComm
{
public:
    /**
     * default constructor
     */
    SnmpComm()
        : mSnmp(0)
        , mTarget(0)
        , mPdu()
    {}

    /**
     * destructor - releases mSnmp and mTarget members, if allocated
     */
    virtual ~SnmpComm()
    {
        delete mSnmp; mSnmp = 0;
        delete mTarget; mTarget = 0;
    }

    /**
     * helper function to extract a signed long integer from snmp vb object
     *
     * @return true on successful conversion, false when not
     */
    static bool extract_value( Vb const &vb, long &l )
    {
        SnmpInt32 i32;
        if( SNMP_CLASS_SUCCESS == vb.get_value( i32 ) )
        {
            l = i32;
            return true;
        }
        return false;
    }

    /**
     * helper function to extract an unsigned long integer from snmp vb object
     *
     * @return true on successful conversion, false when not
     */
    static bool extract_value( Vb const &vb, unsigned long &ul )
    {
        SnmpUInt32 ui32;
        if( SNMP_CLASS_SUCCESS == vb.get_value( ui32 ) )
        {
            ul = ui32;
            return true;
        }
        return false;
    }

    /**
     * helper function to extract a unsigned long long from snmp vb object
     *
     * @return true on successful conversion, false when not
     */
    static bool extract_value( Vb const &vb, unsigned long long &ull )
    {
        Counter64 ui64;
        if( SNMP_CLASS_SUCCESS == vb.get_value( ui64 ) )
        {
            ull = ui64;
            return true;
        }
        return false;
    }

    /**
     * helper function to extract a string from snmp vb object
     *
     * @return true on successful conversion, false when not
     */
    static bool extract_value( Vb const &vb, string &s )
    {
        OctetStr octstr;
        if( SNMP_CLASS_SUCCESS == vb.get_value( octstr ) )
        {
            s = octstr.get_printable();
            return true;
        }
        return false;
    }

    /**
     * build object to parse snmp connection parameters from command line
     *
     * @param snmpopts - the options_description instance to fill with
     *                   option definitions to handle communication to an
     *                   snmp daemon
     */
    void add_snmp_options(options_description &snmpopts) const
    {
        options_description snmpg("General SNMP Options");
        snmpg.add_options()
            ("host,H", value<UdpAddress>()->default_value("127.0.0.1"),
                "host name (or ip address ) of the server to use")
            ("port,p", value<unsigned int>()->default_value(161),
                "port to connect")
            ("snmp-version,V", value<snmp_version>()->default_value(/* XXX version2c */ version1),
                "snmp protocol version")
            ("timeout,t", value<unsigned int>()->default_value(5),
                "timeout in seconds")
            ("retries,r", value<unsigned int>()->default_value(2),
                "amount of retries")
            ;

        options_description snmpv1v2("SNMP V1/V2 options");
        snmpv1v2.add_options()
            ("community,C", value<string>()->default_value("public"),
                "snmp community")
            ;

        options_description snmpv3("SNMP V3 options");
        snmpv3.add_options()
            ("auth-password", value<string>(), "authentication password")
            ("priv-password", value<string>(), "private password")
            ("auth-protocol", value<SnmpV3AuthProtocol>()->default_value(SNMP_AUTHPROTOCOL_NONE),
                "authentication protocol")
            ("priv-protocol", value<SnmpV3PrivProtocol>()->default_value(SNMP_PRIVPROTOCOL_NONE),
                "private protocol")
            ("security-name", value<string>(), "security name")
#if 0
            // for snmpv3, only USM is supported - why enable choosing?
            ("security-model", value<string>() /* FIXME value<snmpSecModel> */,
                "security model")
#endif
            ("security-level", value<SnmpV3SecurityLevel>(), "security level")
            ("context-name", value<string>(), "context name")
            ;


        snmpopts.add(snmpg).add(snmpv1v2).add(snmpv3);
    }

    /**
     * validate snmp connection parameters specified on command line
     */
    void validate_options(variables_map const &vm) const
    {
        if( vm.count("snmp-version") && ( vm["snmp-version"].as<snmp_version>() <= version2c ) )
        {
            if( vm.count("community") == 0 || vm["community"].defaulted() )
                throw option_error(string("SNMPv") + to_string(vm["snmp-version"].as<snmp_version>())
                                   + " requires option 'community'.");
        }
        else
        {
            if( vm.count("security-level") == 0 || vm["security-level"].defaulted() )
                throw option_error("SNMPv3 requires option 'security-level'.");

            SnmpV3SecurityLevel sec_lvl = vm["security-level"].as<SnmpV3SecurityLevel>();
            if( SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV == sec_lvl )
            {
                if( vm["auth-protocol"].as<SnmpV3AuthProtocol>() != SNMP_AUTHPROTOCOL_NONE )
                    throw option_error(string("Option 'auth-protocol' must not be used with a different "
                                       "value than 'none' when 'security-level' is set to '") + to_string(sec_lvl) + "'" );
                if( vm["priv-protocol"].as<SnmpV3PrivProtocol>() != SNMP_PRIVPROTOCOL_NONE )
                    throw option_error(string("Option 'priv-protocol' must not be used with a different "
                                       "value than 'none' when 'security-level' is set to '") + to_string(sec_lvl) + "'" );
            }
            else if( SNMP_SECURITY_LEVEL_AUTH_NOPRIV == sec_lvl )
            {
                if( vm["auth-protocol"].as<SnmpV3AuthProtocol>() == SNMP_AUTHPROTOCOL_NONE )
                    throw option_error(string("Option 'auth-protocol' must not be used with a "
                                       "value of '") + to_string(vm["auth-protocol"].as<SnmpV3AuthProtocol>()) +
                                       "' when 'security-level' is set to '" + to_string(sec_lvl) + "'" );
                if( vm["priv-protocol"].as<SnmpV3PrivProtocol>() != SNMP_PRIVPROTOCOL_NONE )
                    throw option_error(string("Option 'priv-protocol' must not be used with a different "
                                       "value than 'none' when 'security-level' is set to '") + to_string(sec_lvl) + "'" );
            }
            else if( SNMP_SECURITY_LEVEL_AUTH_PRIV == sec_lvl )
            {
                if( vm["auth-protocol"].as<SnmpV3AuthProtocol>() == SNMP_AUTHPROTOCOL_NONE )
                    throw option_error(string("Option 'auth-protocol' must not be used with a "
                                       "value of '") + to_string(vm["auth-protocol"].as<SnmpV3AuthProtocol>()) +
                                       "' when 'security-level' is set to '" + to_string(sec_lvl) + "'" );
                if( vm["priv-protocol"].as<SnmpV3PrivProtocol>() == SNMP_PRIVPROTOCOL_NONE )
                    throw option_error(string("Option 'priv-protocol' must not be used with a "
                                       "value of '") + to_string(vm["priv-protocol"].as<SnmpV3PrivProtocol>()) +
                                       "' when 'security-level' is set to '" + to_string(sec_lvl) + "'" );
            }
            else
            {
                throw validation_error( validation_error::invalid_option_value, to_string(sec_lvl), "security-level" );
            }

            if( vm["auth-protocol"].as<SnmpV3AuthProtocol>() != SNMP_AUTHPROTOCOL_NONE )
            {
                if( ( vm.count("auth-password") == 0 ) || vm["auth-password"].defaulted() )
                    throw option_error( string("Option 'auth-protocol' with the value '") +
                                        to_string(vm["auth-protocol"].as<SnmpV3AuthProtocol>()) +
                                        "' requires the option 'auth-password'" );
            }
            if( vm["priv-protocol"].as<SnmpV3PrivProtocol>() != SNMP_PRIVPROTOCOL_NONE )
            {
                if( ( vm.count("priv-password") == 0 ) || vm["priv-password"].defaulted() )
                    throw option_error( string("Option 'priv-protocol' with the value '") +
                                        to_string(vm["priv-protocol"].as<SnmpV3PrivProtocol>()) +
                                        "' requires the option 'priv-password'" );
            }
        }
    }

    /**
     * configure snmp session upon specified command line parameters
     *
     * @param vm - map of values specified on command line
     */
    void configure(variables_map const &vm)
    {
#ifdef _SNMPv3
        //---------[ init SnmpV3 ]--------------------------------------------
        v3MP *v3_MP;
        if (vm["snmp-version"].as<snmp_version>() == version3)
        {
            const char *engineId = "smart-snmpd-nagios-plugins";
            unsigned int snmpEngineBoots = 0;
            int status;

            v3_MP = new v3MP(engineId, snmpEngineBoots, status);
            if (status != SNMPv3_MP_OK)
                throw runtime_error( string("Error initializing v3MP: ") + to_string(status) );

            USM *usm = v3_MP->get_usm();
            usm->add_usm_user( vm["security-name"].as<string>().c_str(),
                               vm["auth-protocol"].as<SnmpV3AuthProtocol>(), vm["priv-protocol"].as<SnmpV3PrivProtocol>(),
                               vm["auth-password"].as<string>().c_str(), vm["priv-password"].as<string>().c_str() );
        }
        else
        {
            // MUST create a dummy v3MP object if _SNMPv3 is enabled!
            int construct_status;
            v3_MP = new v3MP("dummy", 0, construct_status);
        }
#endif

        //----------[ create a SNMP++ session ]-----------------------------------
        UdpAddress srv = vm["host"].as<UdpAddress>();
        srv.set_port( vm["port"].as<unsigned int>() );

        int status = 0;
        mSnmp = new Snmp( status, 0, (srv.get_ip_version() == Address::version_ipv6) );

        if ( status != SNMP_CLASS_SUCCESS)
        {
            throw runtime_error( string("SNMP++ Session Create Fail, ") + mSnmp->error_msg(status) );
        }

        //--------[ build up SNMP++ object needed ]-------------------------------

        int retries = vm["retries"].as<unsigned int>();
        int timeout = 100 * vm["timeout"].as<unsigned int>(); // in hundreds of seconds
#ifdef _SNMPv3
        if (vm["snmp-version"].as<snmp_version>() == version3)
        {
            mTarget = new UTarget(srv);
            mTarget->set_version(version3);          // set the SNMP version SNMPV1 or V2 or V3
            mTarget->set_retry(retries);            // set the number of auto retries
            mTarget->set_timeout(timeout);          // set timeout

            static_cast<UTarget *>(mTarget)->set_security_model(SNMP_SECURITY_MODEL_USM);
            static_cast<UTarget *>(mTarget)->set_security_name(vm["security-name"].as<string>().c_str());
            mPdu.set_security_level(vm["security-level"].as<SnmpV3SecurityLevel>());
            mPdu.set_context_name(vm["context-name"].as<string>().c_str());
            mPdu.set_context_engine_id(""); // vm["context-engine-id"]
        }
        else
        {
#endif
            mTarget = new CTarget(srv);
            mTarget->set_version( vm["snmp-version"].as<snmp_version>() );         // set the SNMP version SNMPV1 or V2
            mTarget->set_retry(retries);           // set the number of auto retries
            mTarget->set_timeout(timeout);         // set timeout
            static_cast<CTarget *>(mTarget)->set_readcommunity(vm["community"].as<string>().c_str()); // set the read community name
#ifdef _SNMPv3
        }
#endif
    }

    inline bool can_combine_requests() const { return mTarget->get_version() > version1; }

    int get( Vb &varBind )
    {
        Pdu pdu( mPdu ); // start fresh
        pdu.set_vblist( &varBind, 1 );

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get( oid )" );
        LOG( varBind.get_printable_oid() );
        LOG_END;

        int rc = get( pdu );
        if( SNMP_CLASS_SUCCESS != rc )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "get( oid ): rc, error_index" );
            LOG( rc );
            LOG( pdu.get_error_index() );
            LOG_END;
        }

        if( !pdu.get_vb( varBind, 0 ) )
            throw snmp_bad_result( "Can't extract varBind after successful get request" );

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get( oid ): " );
        LOG( string( string( varBind.get_printable_oid() ) + "=" + string( varBind.get_printable_value() ) ).c_str() );
        LOG_END;

        return rc;
    }
    
    int get( vector<Vb> &vblist )
    {
        Pdu pdu( mPdu ); // start fresh
        pdu.set_vblist( &vblist[0], vblist.size() );

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get( vbs )" );
        for( vector<Vb>::iterator i = vblist.begin(); i != vblist.end(); ++i )
        {
            LOG( i->get_printable_oid() );
        }
        LOG_END;

        int rc = get( pdu );
        if( SNMP_CLASS_SUCCESS != rc )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "get( list ): rc, error_index" );
            LOG( rc );
            LOG( pdu.get_error_index() );
            LOG_END;
        }

        if( !pdu.get_vblist( &vblist[0], vblist.size() ) )
        {
            throw snmp_bad_result( "Can't extract varBinds after successful get request" );
        }

        for( vector<Vb>::iterator i = vblist.begin(); i != vblist.end(); ++i )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "received: " );
            LOG( string( string( i->get_printable_oid() ) + "=" + string( i->get_printable_value() ) ).c_str() );
            LOG_END;
        }

        return rc;
    }

    int get_next( Vb &varBind )
    {
        Pdu pdu( mPdu ); // start fresh
        pdu.set_vblist( &varBind, 1 );

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get_next( oid )" );
        LOG( varBind.get_printable_oid() );
        LOG_END;

        int rc = get_next( pdu );
        if( SNMP_CLASS_SUCCESS == rc )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "get_next( oid ): rc, error_index" );
            LOG( rc );
            LOG( pdu.get_error_index() );
            LOG_END;
        }

        if( !pdu.get_vb( varBind, 0 ) )
            throw snmp_bad_result( "Can't extract varBind after successful get_next request" );

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get_next( oid ): " );
        LOG( string( string( varBind.get_printable_oid() ) + "=" + string( varBind.get_printable_value() ) ).c_str() );
        LOG_END;

        return rc;
    }

    int get_next( vector<Vb> &vblist )
    {
        Pdu pdu( mPdu ); // start fresh
        pdu.set_vblist( &vblist[0], vblist.size() );

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get_next( vbs )" );
        for( vector<Vb>::iterator i = vblist.begin(); i != vblist.end(); ++i )
        {
            LOG( i->get_printable_oid() );
        }
        LOG_END;

        int rc = get_next( pdu );
        if( SNMP_CLASS_SUCCESS == rc )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "get_next( list ): rc, error_index" );
            LOG( rc );
            LOG( pdu.get_error_index() );
            LOG_END;
        }

        if( !pdu.get_vblist( &vblist[0], vblist.size() ) )
            throw snmp_bad_result( "Can't extract varBinds after successful get_next request" );

        for( vector<Vb>::iterator i = vblist.begin(); i != vblist.end(); ++i )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "received: " );
            LOG( string( string( i->get_printable_oid() ) + "=" + string( i->get_printable_value() ) ).c_str() );
            LOG_END;
        }

        return rc;
    }

    template < class F >
    int get_bulk( Oid const &start, F &f, int max_reps = BulkMax )
    {
        Pdu pdu( mPdu ); // start fresh
        Vb varBind(start);
        pdu.set_vblist( &varBind, 1 );
        int rc, num_vbs_received;

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get_bulk( oid )" );
        LOG( varBind.get_printable_oid() );
        LOG_END;

        while( ( SNMP_CLASS_SUCCESS == ( rc = get_bulk( pdu, max_reps ) ) )
            && ( 0 != (num_vbs_received = pdu.get_vb_count() ) ) )
        {
	    for( int z = 0; z < num_vbs_received; ++z )
            {
                if( !pdu.get_vb( varBind, z ) )
                    throw snmp_bad_result( "Can't extract varBind after successful get_next request" );

                LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
                LOG( "received: " );
                LOG( string( string( varBind.get_printable_oid() ) + "=" + string( varBind.get_printable_value() ) ).c_str() );
                LOG_END;

                if( varBind.get_syntax() == sNMP_SYNTAX_ENDOFMIBVIEW )
                {
                    goto finish;
                }

                if( ( varBind.get_syntax() == sNMP_SYNTAX_NOSUCHINSTANCE ) ||
                    ( varBind.get_syntax() == sNMP_SYNTAX_NOSUCHOBJECT ) )
                {
                    continue;
                }

                if( f( varBind ) )
                {
                    goto finish;
                }
            }

            varBind.set_null();
            pdu.set_vblist( &varBind, 1 );
        }

        if( SNMP_CLASS_SUCCESS == rc )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "get_bulk( oid ): rc, error_index" );
            LOG( rc );
            LOG( pdu.get_error_index() );
            LOG_END;
        }

finish:
        return rc;
    }

    int get_bulk( Oid const &start, vector<Vb> &result, int max_reps = BulkMax )
    {
        GetBulkFetchHelper fetchHelper( start, result );
        return get_bulk<GetBulkFetchHelper>( start, fetchHelper, max_reps );
    }

    template < class F >
    int get_table( vector<Oid> const &start, F &f, int max_reps = BulkMax )
    {
        Pdu pdu( mPdu ); // start fresh
        vector<Vb> vbVec;

        vbVec.assign( start.begin(), start.end() );

        LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
        LOG( "get_table( vbs )" );
        for( vector<Vb>::iterator i = vbVec.begin(); i != vbVec.end(); ++i )
        {
            LOG( i->get_printable_oid() );
        }
        LOG_END;

        pdu.set_vblist( &vbVec[0], vbVec.size() );
        int rc, num_vbs_received;

        while( ( SNMP_CLASS_SUCCESS == ( rc = get_bulk( pdu, max_reps ) ) )
            && ( 0 != (num_vbs_received = pdu.get_vb_count() ) ) )
        {
            if( ( 1 == num_vbs_received ) && ( pdu.get_vb( 0 ).get_syntax() == sNMP_SYNTAX_ENDOFMIBVIEW ) )
                break;

            if( num_vbs_received % vbVec.size() )
            {
                throw snmp_bad_result( string("Invalid number of results (") + to_string(num_vbs_received) + "), " +
                                       "expected multiple of " + to_string(vbVec.size()) );
            }

            for( int z = 0; z < num_vbs_received; z += vbVec.size() )
            {
                for( typename vector<Vb>::size_type i = 0; i < vbVec.size(); ++i )
                {
                    if( !pdu.get_vb( vbVec[i], z + i ) )
                        throw snmp_bad_result( "Can't extract varBind after successful get_next request" );

                    if( start[i].nCompare( start[i].len(), vbVec[i].get_oid() ) != 0 )
                        goto finish;
                }

                for( vector<Vb>::iterator i = vbVec.begin(); i != vbVec.end(); ++i )
                {
                    LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
                    LOG( "received: " );
                    LOG( string( string( i->get_printable_oid() ) + "=" + string( i->get_printable_value() ) ).c_str() );
                    LOG_END;
                }

                if( f( vbVec ) )
                {
                    goto finish;
                }
            }

            for( vector<Vb>::iterator i = vbVec.begin(); i != vbVec.end(); ++i )
                i->set_null();
            pdu.set_vblist( &vbVec[0], vbVec.size() );
        }

        if( SNMP_CLASS_SUCCESS == rc )
        {
            LOG_BEGIN( loggerModuleName, DEBUG_LOG | 13 );
            LOG( "get_table( list ): rc, error_index" );
            LOG( rc );
            LOG( pdu.get_error_index() );
            LOG_END;
        }

finish:
        return rc;
    }

    int get_table( vector<Oid> const &start, vector< vector<Vb> > &result, int max_reps = BulkMax )
    {
        GetBulkFetchTableHelper fetchTableHelper( result );
        return get_table<GetBulkFetchTableHelper>( start, fetchTableHelper, max_reps );
    }

protected:
    /**
     * snmp session object
     */
    Snmp *mSnmp;
    /**
     * target server identifier
     */
    SnmpTarget *mTarget;
    /**
     * protocol data unit to parametrize snmp requests
     */
    Pdu mPdu;

    /**
     * requests and fetches configured values
     *
     * @return value from Snmp::get
     */
    int get( Pdu &pdu )
    {
        return mSnmp->get( pdu, *mTarget );
    }

    /**
     * requests and fetches next configured values
     *
     * @return value from Snmp::get_next
     */
    int get_next( Pdu &pdu )
    {
        return mSnmp->get_next( pdu, *mTarget );
    }

    /**
     * bulk-requests and fetches configured values
     *
     * @return value from Snmp::get_bulk
     */
    int get_bulk( Pdu &pdu, int max_reps = BulkMax )
    {
        return mSnmp->get_bulk( pdu, *mTarget, 0, max_reps );
    }
};

#undef loggerModuleName

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_SNMP_COMM_H_INCLUDED__ */
