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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_COMM_TYPES_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_COMM_TYPES_H_INCLUDED__

#include <smart-snmpd-nagios-plugins/snmp-pp-std.h>

/**
 * @brief wrapper class for SNMPv3 auth protocol constants for program option parsing
 *
 * This class is an adapter for SNMPv3 authentication protocol identifier constants
 * from snmp++ library and a human readable representation for user interaction.
 */
class SnmpV3AuthProtocol
{
public:
    /**
     * @brief standard and cast from long constructor
     *
     * @param auth_proto authentication protocol identifier
     */
    SnmpV3AuthProtocol(long int auth_proto = SNMP_AUTHPROTOCOL_NONE)
        : mAuthProto(auth_proto)
    {}

    //! copy constructor
    SnmpV3AuthProtocol(SnmpV3AuthProtocol const &r)
        : mAuthProto(r.mAuthProto)
    {}

    //! destructor
    ~SnmpV3AuthProtocol() {}

    //! assignment operator
    inline SnmpV3AuthProtocol & operator = (SnmpV3AuthProtocol const &r) { mAuthProto = r.mAuthProto; return *this; }
    //! cast operator into long int
    inline operator long () const { return mAuthProto; }

protected:
    /**
     * @brief managed auth-protocol value
     *
     * Can contain one of following values:
     * SNMP_AUTHPROTOCOL_NONE, SNMP_AUTHPROTOCOL_HMACMD5, SNMP_AUTHPROTOCOL_HMACSHA
     */
    long int mAuthProto;
};

/**
 * @brief specialization to convert SnmpV3AuthProtocol into an STL string
 *
 * @param ap - authentication protocol identifier
 */
template<>
std::string
to_string(SnmpV3AuthProtocol const &ap)
{
    switch( ap )
    {
    case SNMP_AUTHPROTOCOL_HMACMD5:
        return "md5";

    case SNMP_AUTHPROTOCOL_HMACSHA:
        return "sha";

    case SNMP_AUTHPROTOCOL_NONE:
        return "none";

    default:
        return string("invalid(") + to_string( static_cast<long>(ap) ) + ")";
    }
}

/**
 * overloaded stream output operator for SnmpV3AuthProtocol objects
 */
inline ostream &
operator << (ostream &os, SnmpV3AuthProtocol const &v)
{
    return os << to_string(v);
}

/**
 * overloaded stream input operator for SnmpV3AuthProtocol objects
 */
inline istream &
operator >> (istream &is, SnmpV3AuthProtocol &v)
{
    string s;
    is >> s;

    locase(s);

    if( s == "none" )
        v = SNMP_AUTHPROTOCOL_NONE;
    else if( s == "md5" )
        v = SNMP_AUTHPROTOCOL_HMACMD5;
    else if( s == "md5" )
        v = SNMP_AUTHPROTOCOL_HMACSHA;
    else
        throw invalid_value_execption(s + " -> SnmpV3AuthProtocol");

    return is;
}

/**
 * @brief wrapper class for SNMPv3 privacy protocol constants for program option parsing
 *
 * This class is an adapter for SNMPv3 privacy protocol identifier constants
 * from snmp++ library and a human readable representation for user interaction.
 */
class SnmpV3PrivProtocol
{
public:
    /**
     * @brief standard and cast from long constructor
     *
     * @param priv_proto privacy identifier
     */
    SnmpV3PrivProtocol(long int priv_proto = SNMP_PRIVPROTOCOL_NONE)
        : mPrivProto(priv_proto)
    {}

    //! copy constructor
    SnmpV3PrivProtocol(SnmpV3PrivProtocol const &r)
        : mPrivProto(r.mPrivProto)
    {}

    //! destructor
    ~SnmpV3PrivProtocol() {}

    //! assignment operator
    inline SnmpV3PrivProtocol & operator = (SnmpV3PrivProtocol const &r) { mPrivProto = r.mPrivProto; return *this; }
    //! cast operator into long int
    inline operator long () const { return mPrivProto; }

protected:
    /**
     * @brief managed priv-protocol value
     *
     * Can contain one of following values:
     * SNMP_PRIVPROTOCOL_NONE, SNMP_PRIVPROTOCOL_DES, SNMP_PRIVPROTOCOL_AES128,
     * SNMP_PRIVPROTOCOL_IDEA, SNMP_PRIVPROTOCOL_AES192, SNMP_PRIVPROTOCOL_AES256,
     * SNMP_PRIVPROTOCOL_3DESEDE
     */
    long int mPrivProto;
};

/**
 * specialized function to cast SnmpV3PrivProtocol into std::string
 *
 * @param pp - the SNMPv3 privacy protocol identifier
 * @return std::string - stringified priv protocol (human readable)
 */
template<>
std::string
to_string(SnmpV3PrivProtocol const &pp)
{
    switch( pp )
    {
    case SNMP_PRIVPROTOCOL_DES:
        return "des";

    case SNMP_PRIVPROTOCOL_3DESEDE:
        return "3des";

    case SNMP_PRIVPROTOCOL_IDEA:
        return "idea";

    case SNMP_PRIVPROTOCOL_AES128:
        return "aes128";

    case SNMP_PRIVPROTOCOL_AES192:
        return "aes192";

    case SNMP_PRIVPROTOCOL_AES256:
        return "aes256";

    case SNMP_PRIVPROTOCOL_NONE:
        return "none";

    default:
        return string("invalid(") + to_string( static_cast<long>(pp) ) + ")";
    }
}

/**
 * overloaded stream output operator for SnmpV3PrivProtocol objects
 */
inline ostream &
operator << (ostream &os, SnmpV3PrivProtocol const &v)
{
    return os << to_string(v);
}

/**
 * overloaded stream input operator for SnmpV3PrivProtocol objects
 */
inline istream &
operator >> (istream &is, SnmpV3PrivProtocol &v)
{
    string s;
    is >> s;

    locase(s);

    if( s == "none" )
        v = SNMP_PRIVPROTOCOL_NONE;
    else if( s == "des" )
        v = SNMP_PRIVPROTOCOL_DES;
    else if( s == "3des" )
        v = SNMP_PRIVPROTOCOL_IDEA;
    else if( s == "idea" )
        v = SNMP_PRIVPROTOCOL_DES;
    else if( s == "aes128" )
        v = SNMP_PRIVPROTOCOL_AES128;
    else if( s == "aes192" )
        v = SNMP_PRIVPROTOCOL_AES192;
    else if( s == "aes256" )
        v = SNMP_PRIVPROTOCOL_AES256;
    else
        throw invalid_value_execption(s + " -> SnmpV3PrivProtocol");

    return is;
}

#if 0
class SnmpV3SecurityModel
{
public:
    SnmpV3SecurityModel(long int sec_model = SNMP_SECURITY_MODEL_USM)
        : mSecurityLevel(sec_lvl)
    {}
    SnmpV3SecurityModel(SnmpV3SecurityModel const &r)
        : mSecurityLevel(r.mSecurityModel)
    {}

    ~SnmpV3SecurityModel() {}

    inline SnmpV3SecurityModel & operator = (SnmpV3SecurityModel const &r) { mSecurityModel = r.mSecurityModel; return *this; }
    inline operator long () const { return mSecurityModel; }

protected:
    long int mSecurityModel;
};
#endif

/**
 * @brief wrapper class for SNMPv3 security level constants for program option parsing
 *
 * This class is an adapter for SNMPv3 security level identifier constants
 * from snmp++ library and a human readable representation for user interaction.
 */
class SnmpV3SecurityLevel
{
public:
    /**
     * @brief standard and cast from long constructor
     *
     * @param sec_lvl security level identifier
     */
    SnmpV3SecurityLevel(long int sec_lvl = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV)
        : mSecurityLevel(sec_lvl)
    {}

    //! copy constructor
    SnmpV3SecurityLevel(SnmpV3SecurityLevel const &r)
        : mSecurityLevel(r.mSecurityLevel)
    {}

    //! destructor
    ~SnmpV3SecurityLevel() {}

    //! assignment operator
    inline SnmpV3SecurityLevel & operator = (SnmpV3SecurityLevel const &r) { mSecurityLevel = r.mSecurityLevel; return *this; }
    //! cast operator into long int
    inline operator long () const { return mSecurityLevel; }

protected:
    /**
     * @brief managed security level value
     *
     * Can contain one of following values:
     * SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV, SNMP_SECURITY_LEVEL_AUTH_NOPRIV, SNMP_SECURITY_LEVEL_AUTH_PRIV
     */
    long int mSecurityLevel;
};

/**
 * specialized function to cast SnmpV3SecurityLevel into std::string
 *
 * @param sl - the SNMPv3 Priv Protocol
 * @return std::string - stringified security level (human readable)
 */
template<>
std::string
to_string(SnmpV3SecurityLevel const &sl)
{
    switch( sl )
    {
    case SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV:
        return "noauth,nopriv";

    case SNMP_SECURITY_LEVEL_AUTH_NOPRIV:
        return "auth,nopriv";

    case SNMP_SECURITY_LEVEL_AUTH_PRIV:
        return "auth,priv";

    default:
        return string("invalid(") + to_string( static_cast<long>(sl) ) + ")";
    }
}

/**
 * overloaded stream output operator for SnmpV3SecurityLevel objects
 */
inline ostream &
operator << (ostream &os, SnmpV3SecurityLevel const &v)
{
    return os << to_string(v);
}

/**
 * overloaded stream input operator for SnmpV3SecurityLevel objects
 */
inline istream &
operator >> (istream &is, SnmpV3SecurityLevel &v)
{
    string s;
    is >> s;

    locase(s);

    if( ( s == "none" ) || ( s == "noauth" ) || ( s == "noauth,nopriv" ) )
        v = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
    else if( ( s == "nopriv" ) || ( s == "auth,nopriv" ) )
        v = SNMP_SECURITY_LEVEL_AUTH_NOPRIV;
    else if( ( s == "auth,priv" ) || ( s == "full" ) )
        v = SNMP_SECURITY_LEVEL_AUTH_PRIV;
    else
        throw invalid_value_execption(s + " -> SnmpV3SecurityLevel");

    return is;
}

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_SNMP_COMM_TYPES_H_INCLUDED__ */
