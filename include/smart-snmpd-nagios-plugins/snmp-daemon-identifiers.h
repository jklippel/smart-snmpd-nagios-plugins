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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_SUPPORTED_MIB_MAP_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_SUPPORTED_MIB_MAP_H_INCLUDED__

#include <smart-snmpd-nagios-plugins/snmp-pp-std.h>

#include <map>
#include <functional>

using namespace std;

#include <boost/tuple/tuple.hpp>

using namespace boost;

class SnmpDaemonIdentifier
    : public boost::tuple<string,Oid,string>
{
public:
    SnmpDaemonIdentifier(string const &mib_name, Oid const &prove_oid, string const &prove_value)
        : boost::tuple<string,Oid,string>(mib_name, prove_oid, prove_value)
    {}

    virtual ~SnmpDaemonIdentifier() {}

    string const & getName() const { return get<0>(); }
    Oid const & getProveOid() const { return get<1>(); }
    string const & getProveValue() const { return get<2>(); }

    bool proveValue(string const &cmp) const
    {
        string const &src = getProveValue();
        return 0 == cmp.find( src );
    }

private:
    SnmpDaemonIdentifier();
};

inline
bool
operator == (SnmpDaemonIdentifier const &x, SnmpDaemonIdentifier const &y)
{
    return x.getName() == y.getName();
}

inline
bool
operator != (SnmpDaemonIdentifier const &x, SnmpDaemonIdentifier const &y)
{
    return x.getName() != y.getName();
}

inline
bool
operator <= (SnmpDaemonIdentifier const &x, SnmpDaemonIdentifier const &y)
{
    return x.getName() <= y.getName();
}

inline
bool
operator >= (SnmpDaemonIdentifier const &x, SnmpDaemonIdentifier const &y)
{
    return x.getName() >= y.getName();
}

inline
bool
operator < (SnmpDaemonIdentifier const &x, SnmpDaemonIdentifier const &y)
{
    return x.getName() < y.getName();
}

inline
bool
operator > (SnmpDaemonIdentifier const &x, SnmpDaemonIdentifier const &y)
{
    return x.getName() > y.getName();
}

static const SnmpDaemonIdentifier IdentifySmartSnmpdMib( "smart-snmpd", SYS_OBJECT_ID ".0", SM_MAHAAG_MIB );
static const SnmpDaemonIdentifier IdentifyNetSnmpd( "net-snmpd", SYS_OBJECT_ID ".0", "1.3.6.1.4.1.8072" );

class AnyDataType
    : public boost::any
{
public:
    AnyDataType() : boost::any() {}
    AnyDataType( boost::any const &r ) : boost::any(r) {}
    AnyDataType( AnyDataType const &r ) : boost::any( static_cast<boost::any const &>( r ) ) {}

    template < class T >
    T const & as() const { return boost::any_cast<T const &>( *this ); }
    template < class T >
    T & as() { return boost::any_cast<T &>( *this ); }
};

class AnyDataMap
: public std::map< std::string, AnyDataType >
{
public:
    using std::map< std::string, AnyDataType >::operator [];
    AnyDataType const & operator [] ( const std::string &key ) const
    {
        const_iterator ci = lower_bound( key );
        if( ci != end() )
            return ci->second;
        else
            return mEmpty;
    }

private:
    static const AnyDataType mEmpty;
};

const AnyDataType AnyDataMap::mEmpty = AnyDataType();
static const string ProveValueMapKey = "[prove_value]";

class SupportedMibData
{
public:
    // typedef std::map< std::string, AnyDataType > DataMapType;
    typedef AnyDataMap DataMapType;

    SupportedMibData( vector<Oid> const &dataOids )
        : mDataOids( dataOids )
    {}

    virtual ~SupportedMibData() {}

    virtual vector<Oid> const & getDataOids() const { return mDataOids; }
    virtual void convertSnmpData( vector<Vb> const &vblist, DataMapType &dataMap ) = 0;

protected:
    const vector<Oid> mDataOids;

private:
    SupportedMibData();
};

class SupportedMibDataTable
    : public SupportedMibData
{
public:
    SupportedMibDataTable( vector<Oid> const &dataOids, vector<Oid> const &rowSearchColumnOids )
        : SupportedMibData( dataOids )
        , mRowSearchColumnOids( rowSearchColumnOids )
        , mFoundRowIndex( -1 )
        , mTableOids()
    {}

    virtual ~SupportedMibDataTable() {}

    SupportedMibDataTable & setFoundRowIndex( long foundRowIndex )
    {
        mFoundRowIndex = foundRowIndex;

        mTableOids.clear();
        mTableOids.reserve( mDataOids.size() );
        for( vector<Oid>::const_iterator ci = mDataOids.begin(); ci != mDataOids.end(); ++ci )
        {
            Oid fullOid = *ci;
            fullOid += foundRowIndex;
            mTableOids.push_back( fullOid );
        }

        return *this;
    }

    virtual vector<Oid> const & getDataOids() const { return mTableOids; }

    vector<Oid> const & getRowSearchColumnOids() const { return mRowSearchColumnOids; }

protected:
    const vector<Oid> mRowSearchColumnOids;
    long mFoundRowIndex;
    vector<Oid> mTableOids;

private:
    SupportedMibDataTable();
};

#endif /* ?__SMART_SNMPD_NAGIOS_CHECKS_SNMP_SUPPORTED_MIB_MAP_H_INCLUDED__ */
