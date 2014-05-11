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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_STD_EXT_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_STD_EXT_H_INCLUDED__

#include <exception>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cctype>

using namespace std;

#include <boost/lexical_cast.hpp>

class invalid_value_execption
    : public logic_error
{
public:
    explicit invalid_value_execption(const string &what_arg) throw()
        : logic_error(what_arg)
    {}

    invalid_value_execption(invalid_value_execption const &e) throw()
        : logic_error(e)
    {}

    virtual ~invalid_value_execption() throw() {}

    invalid_value_execption & operator = (invalid_value_execption const &e) throw() { logic_error::operator =(e); return *this; }

    virtual const char* what() const throw()
    {
        try
        {
            string s = "invalid value: ";
            s += logic_error::what();
            return s.c_str();
        }
        catch(std::exception &e)
        {
            return logic_error::what();
        }
    }
};

/**
 * helper object to create a vector from a fixed size C array
 *
 * @param values - fixed size C array of N elements of type T
 *
 * @return vector containing N elements of type T
 */
template<class T, size_t N>
vector<T>
make_vector( const T values[N] )
{
    vector<T> v;
    v.reserve(N);
    for( size_t i = 0; i < N; ++i )
        v.push_back( values[i] );
    return v;
}

/**
 * helper object to create a vector of pointers from a fixed size C array
 *
 * @param values - fixed size C array of N elements of type T * const
 *
 * @return vector containing N elements of type T * const
 */
template<class T, size_t N>
vector<T *>
make_ptr_vector( T * const values[N] )
{
    vector< T *> v;
    v.reserve(N);
    for( size_t i = 0; i < N; ++i )
        v.push_back( values[i] );
    return v;
}

template<typename T>
std::string
to_string(T const &v)
{
    return boost::lexical_cast<std::string>(v);
}

template<>
std::string
to_string(double const &d)
{
    ostringstream oss;
    oss << fixed << setprecision(2) << d;
    return oss.str();
}

template< class Ch, class Tr, class A >
basic_string<Ch, Tr, A> &
upcase(basic_string<Ch, Tr, A> &s)
{
    for( string::iterator i = s.begin(); i != s.end(); ++i )
        *i = toupper(*i);

    return s;
}

template< class Ch, class Tr, class A >
basic_string<Ch, Tr, A> &
locase(basic_string<Ch, Tr, A> &s)
{
    for( string::iterator i = s.begin(); i != s.end(); ++i )
        *i = tolower(*i);

    return s;
}

namespace boost
{

template<>
std::string
lexical_cast<std::string>( bool const &v )
{
    return v ? "true" : "false";
}

}

string
join( string const &delim, vector<string> const &list )
{
    string rc;

    for( vector<string>::const_iterator ci = list.begin(); ci != list.end(); ++ci )
    {
        if( !rc.empty() )
            rc += delim;
        rc += *ci;
    }

    return rc;
}

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_STD_EXT_H_INCLUDED__ */
