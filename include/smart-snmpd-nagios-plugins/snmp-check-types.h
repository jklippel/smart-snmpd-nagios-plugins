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
#ifndef __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_TYPES_H_INCLUDED__
#define __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_TYPES_H_INCLUDED__

#include <functional>

using namespace std;

#include <boost/tuple/tuple.hpp>

using namespace boost;

/**
 * base class for thresholds for warning/critical thresholds and finally the values got from the snmpd
 *
 * This class manages the basic thresholds to compare the values
 * got from the snmp daemon against the warning/critical thresholds from
 * the initiator.
 * Compare operations are always false when the second operand is empty.
 */
template <class T>
class Threshold
{
public:
    /**
     * default constructor - constructs an empty threshold
     */
    Threshold()
        : mValue()
        , mEmpty(true)
    {}

    /**
     * constructor - constructs a non-empty threshold with value
     *
     * @param v - the value for the threshold
     */
    Threshold(T const &v)
        : mValue(v)
        , mEmpty(false)
    {}

    /**
     * copy constructor
     */
    Threshold(Threshold const &r)
        : mValue(r.mValue)
        , mEmpty(r.mEmpty)
    {}

    /**
     * destructor
     */
    virtual ~Threshold() {}

    /**
     * assignment operator
     *
     * @param r - threshold to assign
     *
     * @return reference to this instance
     */
    inline Threshold & operator = (Threshold const &r) { mValue = r.mValue; mEmpty = r.mEmpty; return *this; }
    // inline Threshold & operator = (T const &v) { mValue = v; mEmpty = false; return *this; }

    /**
     * tells whether this instance contains a value or not
     *
     * @return bool - true if instance is empty, false if it contains a value
     */
    inline bool empty() const { return mEmpty; }

    /**
     * conversion operator to contained type
     *
     * @return T - the contained value if any, the default value if empty
     */
    inline operator T () const { return mValue; }

protected:
    /**
     * value of the threshold
     */
    T mValue;
    /**
     * flags whether threshold is empty or not
     */
    bool mEmpty;
};

/**
 * compares two Threshold instances for equality
 *
 * This operator compares two given thresholds whereby x must not be empty.
 * In case that y is empty, the equality check always returns false.
 *
 * @param x - first compare operand
 * @param y - second compare operand
 *
 * @return bool - true if y is not empty and x == y, false otherwise
 */
template<class T>
inline bool operator == ( Threshold<T> const &x, Threshold<T> const &y )
{
    bool rc = false;
    if( !y.empty() )
        rc |= ((T)x == (T)y);
    return rc;
}

/**
 * compares two Threshold instances for inequality
 *
 * This operator compares two given thresholds whereby x must not be empty.
 * In case that y is empty, the equality check always returns false.
 *
 * @param x - first compare operand
 * @param y - second compare operand
 *
 * @return bool - true if y is not empty and x != y, false otherwise
 */
template<class T>
inline bool operator != ( Threshold<T> const &x, Threshold<T> const &y )
{
    return !(x == y);
}

/**
 * compares two Threshold instances for falling below
 *
 * This operator compares two given thresholds whereby x must not be empty.
 * In case that y is empty, the equality check always returns false.
 *
 * @param x - first compare operand
 * @param y - second compare operand
 *
 * @return bool - true if y is not empty and x < y, false otherwise
 */
template<class T>
inline bool operator < ( Threshold<T> const &x, Threshold<T> const &y )
{
    bool rc = false;
    if( !y.empty() )
        rc |= ((T)x < (T)y);
    return rc;
}

/**
 * compares two Threshold instances for falling below or equality
 *
 * This operator compares two given thresholds whereby x must not be empty.
 * In case that y is empty, the equality check always returns false.
 *
 * @param x - first compare operand
 * @param y - second compare operand
 *
 * @return bool - true if y is not empty and x <= y, false otherwise
 */
template<class T>
inline bool operator <= ( Threshold<T> const &x, Threshold<T> const &y )
{
    return (x == y) || (x < y);
}

/**
 * compares two Threshold instances for exceeding
 *
 * This operator compares two given thresholds whereby x must not be empty.
 * In case that y is empty, the equality check always returns false.
 *
 * @param x - first compare operand
 * @param y - second compare operand
 *
 * @return bool - true if y is not empty and x > y, false otherwise
 */
template<class T>
inline bool operator > ( Threshold<T> const &x, Threshold<T> const &y )
{
    bool rc = false;
    if( !y.empty() )
        rc |= ((T)x > (T)y);
    return rc;
}

/**
 * compares two Threshold instances for exceeding or equality
 *
 * This operator compares two given thresholds whereby x must not be empty.
 * In case that y is empty, the equality check always returns false.
 *
 * @param x - first compare operand
 * @param y - second compare operand
 *
 * @return bool - true if y is not empty and x >= y, false otherwise
 */
template<class T>
inline bool operator >= ( Threshold<T> const &x, Threshold<T> const &y )
{
    return (x == y) || (x > y);
}

/**
 * output the value of the threshold into a stream
 *
 * This operator writes the content of the given threshold into the given
 * stream. In case the threshold is empty, '-' is written, the contained
 * value otherwise.
 *
 * @param os - the output stream to write into
 * @param v - the threshold value
 *
 * @return the output stream
 */
template<class T>
inline ostream &
operator << (ostream &os, Threshold<T> const &v)
{
    if( v.empty() )
    {
        return os << "-";
    }
    else
    {
        T tv = v;
        return os << tv;
    }
}

/**
 * read the threshold from a stream
 *
 * This operator reads threshold contents from the given input stream. A
 * single '-' is interpreted as empty threshold, otherwise the entire read
 * first word is converted to the value type.
 *
 * @param is - the input stream to read from
 * @param v - the threshold to read into
 *
 * @return the input stream
 */
template<class T>
inline istream &
operator >> (istream &is, Threshold<T> &v)
{
    string s;
    is >> s;
    if( s == "-" )
        v = Threshold<T>();
    else
    {
        istringstream iss(s);
        T tv;
        iss >> tv;
        v = tv;
    }

    return is;
}

/**
 * specialization of generic to_string for threshold
 *
 * @param t - threshold to convert
 *
 * @return string representation of given threshold
 */
template<class T>
std::string
to_string(Threshold<T> const &t)
{
    if( t.empty() )
        return "-";
    else
    {
        T v = t;
        return to_string( v );
    }
}

/**
 * Overload the 'validate' function for non-specialized Threshold classes.
 * It makes sure that value is either an integer value with
 * optional multiplier extension or a floating point value
 * with percent extenstion. */
template< class T >
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              Threshold<T> *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    any tmp;
    validate( tmp, values, (T *)0, 0 );
    v = any( Threshold<T>( any_cast<T>( tmp ) ) );
}

/**
 * often used short-cut for storing absolute thresholds
 */
typedef Threshold<unsigned long long> AbsoluteThreshold;

/**
 * often used specialization to deal with relative thresholds (e.g. 50%)
 *
 * Relative thresholds are especially used to scan command line input,
 * whereby x% is internally stored as x/100. Beside this minor difference,
 * RelativeThreshold behaves as it's base class Threshold<double>.
 */
class RelativeThreshold
    : public Threshold<double>
{
public:
    /**
     * default constructor - creates empty RelativeThreshold
     */
    RelativeThreshold()
        : Threshold<double>()
    {}

    /**
     * constructor from value
     *
     * @param v - the initial value for this threshold
     */
    RelativeThreshold(double const &v)
        : Threshold<double>(v)
    {}

    /**
     * copy constructor
     *
     * @param r - reference to initialize this instance from
     */
    RelativeThreshold(RelativeThreshold const &r)
        : Threshold<double>(r)
    {}

    /**
     * conversion constructor from base class
     *
     * @param r - reference to initialize this instance from
     */
    RelativeThreshold(Threshold<double> const &r)
        : Threshold<double>(r)
    {}

    /**
     * assignment operator
     *
     * @param r - reference of another threshold to assign it to this one
     *
     * @return reference to this instance
     */
    inline RelativeThreshold & operator = (RelativeThreshold const &r) { Threshold<double>::operator = (r); return *this; }
};

/**
 * Overload the 'validate' function for the RelativeThreshold class.
 * It makes sure that value is either an integer value with
 * optional multiplier extension or a floating point value
 * with percent extenstion. */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              RelativeThreshold *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);
    string::const_iterator se = s.end();
    double divisor = 1.0;

    if( s[s.length() - 1] == '%' ) {
        --se;
        divisor = 100.00;
    }

    try
    {
        double d = lexical_cast<double>( string( s.begin(), se ) );
        d /= divisor;
        v = any( RelativeThreshold( d ) );
    }
    catch(std::exception &e)
    {
        throw validation_error(validation_error::invalid_option_value, s);
    }
}

/**
 * often used specialization to deal with thresholds for sizes in bytes (e.g. 10M)
 *
 * BytesThreshold are especially used to scan command line input,
 * whereby nk is internally stored as n*1024. The supported factors are
 * from k=1024 over m=1024*1024 up to p=1024^5. Beside this minor
 * difference, BytesThreshold behaves as it's base class AbsoluteThreshold
 * (which is finally an Threshold<unsigned long long>).
 */
class BytesThreshold
    : public AbsoluteThreshold
{
public:
    /**
     * default constructor - creates empty BytesThreshold
     */
    BytesThreshold()
        : AbsoluteThreshold()
    {}

    /**
     * constructor from value
     *
     * @param v - the initial value for this threshold
     */
    BytesThreshold(unsigned long long const &v)
        : AbsoluteThreshold(v)
    {}

    /**
     * copy constructor
     *
     * @param r - reference to initialize this instance from
     */
    BytesThreshold(BytesThreshold const &r)
        : AbsoluteThreshold(r)
    {}

    /**
     * conversion constructor from base class
     *
     * @param r - reference to initialize this instance from
     */
    BytesThreshold(AbsoluteThreshold const &r)
        : AbsoluteThreshold(r)
    {}

    /**
     * assignment operator
     *
     * @param r - reference of another threshold to assign it to this one
     *
     * @return reference to this instance
     */
    inline BytesThreshold & operator = (BytesThreshold const &r) { AbsoluteThreshold::operator = (r); return *this; }
};

/**
 * Overload the 'validate' function for the BytesThreshold class.
 * It makes sure that value is either an integer value with
 * optional multiplier extension or a floating point value
 * with percent extenstion.
 * The supported factors are from k=1024 over m=1024*1024 and
 * g=1024^3 and t=1024^4 up to p=1024^5.
 */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              BytesThreshold *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);
    string::const_iterator se = s.end();

    unsigned long long multiplier = 1;

    if( !isdigit(s[s.length() - 1]) )
    {
        switch( s[s.length() - 1] )
        {
        case 'k':
        case 'K':
            multiplier = 1024;
            break;

        case 'm':
        case 'M':
            multiplier = 1024 * 1024;
            break;

        case 'g':
        case 'G':
            multiplier = 1024 * 1024 * 1024;
            break;

        case 't':
        case 'T':
            multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;

        case 'p':
        case 'P':
            multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
            break;

        default:
            throw validation_error(validation_error::invalid_option_value, s);
        }
        --se;
    }

    v = any( BytesThreshold( lexical_cast<unsigned long long>( string( s.begin(), se ) ) * multiplier ) );
}

/**
 * specialization for absolute or releative threshold
 *
 * This specialization combines two thresholds for comparing
 * sizes. Sizes in information technology always have an upper
 * limit, which represents 100% (RelativeThreshold).
 */
class SizeThreshold
    : public boost::tuple<BytesThreshold,RelativeThreshold>
{
public:
    /**
     * default constructor - creates empty SizeThreshold
     */
    SizeThreshold()
        : boost::tuple<BytesThreshold,RelativeThreshold>()
    {}

    /**
     * constructor from absolute value
     *
     * @param abs - the initial absolute value for this threshold, the
     *              relative value remains empty
     */
    SizeThreshold(BytesThreshold const &abs)
        : boost::tuple<BytesThreshold,RelativeThreshold>( abs, RelativeThreshold() )
    {}

    /**
     * constructor from relative value
     *
     * @param rel - the initial relative value for this threshold, the
     *              absolute value remains empty
     */
    SizeThreshold(RelativeThreshold const &rel)
        : boost::tuple<BytesThreshold,RelativeThreshold>( BytesThreshold(), rel )
    {}

    /**
     * constructor from both values
     *
     * @param abs - the initial absolute value for this threshold
     * @param rel - the initial relative value for this threshold
     */
    SizeThreshold(BytesThreshold const &abs, RelativeThreshold const &rel)
        : boost::tuple<BytesThreshold,RelativeThreshold>( abs, rel )
    {}

    /**
     * constructor from both values in reverse order
     *
     * @param rel - the initial relative value for this threshold
     * @param abs - the initial absolute value for this threshold
     */
    SizeThreshold(RelativeThreshold const &rel, BytesThreshold const &abs)
        : boost::tuple<BytesThreshold,RelativeThreshold>( abs, rel )
    {}

    /**
     * copy constructor
     *
     * @param r - reference to initialize this instance from
     */
    SizeThreshold(SizeThreshold const &r)
        : boost::tuple<BytesThreshold,RelativeThreshold>(r)
    {}

    /**
     * assignment operator
     *
     * @param r - reference of another threshold to assign it to this one
     *
     * @return reference to this instance
     */
    inline SizeThreshold & operator = (SizeThreshold const &r) { boost::tuple<BytesThreshold,RelativeThreshold>::operator = (r); return *this; }

    /**
     * approves whether we have can represent an absolute threshold or not
     *
     * @return bool - true when an absolute value is available which can be used
     */
    inline bool is_abs() const { return !get<0>().empty(); }
    /**
     * approves whether we have can represent a relative threshold or not
     *
     * @return bool - true when a relative value is available which can be used
     */
    inline bool is_rel() const { return !get<1>().empty(); }
    /**
     * delivers the absolute value of this threshold
     *
     * @return the absolute threshold of this tuple
     */
    inline BytesThreshold const & absolute() const { return get<0>(); }
    /**
     * delivers the relative value of this threshold
     *
     * @return the relative threshold of this tuple
     */
    inline RelativeThreshold const & relative() const { return get<1>(); }
};

/**
 * Overload the 'validate' function for the SizeThreshold class.
 * It makes sure that value is either an integer value with
 * optional multiplier extension or a floating point value
 * with percent extenstion or both values, comma separated.
 */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              SizeThreshold *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);
    string::size_type sb, st = 0;
    BytesThreshold abs;
    RelativeThreshold rel;

    while( st != string::npos )
    {
        boost::any tmp;

        if( st != 0 )
            ++st;
        st = s.find( ',', sb = st );

        if( !abs.empty() && !rel.empty() )
            throw validation_error(validation_error::invalid_option_value, s);

        string stmp( s, sb, st - sb );
        vector<string> vs;
        vs.push_back( stmp );

        if( abs.empty() )
        {
            try
            {
                validate( tmp, vs, &abs, 0);
                abs = any_cast<BytesThreshold>(tmp);
                continue;
            }
            catch(validation_error &e) { /* discard */ }
        }

        if( rel.empty() )
        {
            validate( tmp, vs, &rel, 0);
            rel = any_cast<RelativeThreshold>(tmp);
            continue;
        }

        throw validation_error(validation_error::invalid_option_value, s);
    }

    v = any( SizeThreshold( abs, rel ) );
}

/**
 * compare predicate for sizes
 */
template < class AbsCmp = less_equal<BytesThreshold>, class RelCmp = greater_equal<RelativeThreshold> >
class AbsoluteRelativeCmp
    : public binary_function<BytesThreshold, BytesThreshold, bool>
{
public:
    /**
     * default constructor
     */
    AbsoluteRelativeCmp()
        : mAbsCmp()
        , mRelCmp()
    {}

    /**
     * compare operator
     *
     * This operator returns true if at least one of the aggregated comparators
     * return true. At default configuration this means, if either the absolute
     * threshold of x is less or equal compared to the absolute threshold of y or
     * the relative threshold of x is greater or equal compared to the relative
     * threshold of y.
     *
     * @param x - usually the determined size via snmp
     * @param y - usually the initiator specified threshold
     *
     * @return bool - true when either the absolute compare is true or the
     *                relative compare is true, false otherwise
     */
    inline bool operator () (SizeThreshold const &x, SizeThreshold const &y) const
    {
        bool rc = false;

        rc |= mAbsCmp( x.absolute(), y.absolute() );
        rc |= mRelCmp( x.relative(), y.relative() );

        return rc;
    }

protected:
    /**
     * compare predicate for the absolute part of the size
     */
    AbsCmp mAbsCmp;
    /**
     * compare predicate for the relative part of the size
     */
    RelCmp mRelCmp;
};

/**
 * often used specialization to deal with thresholds for timestamps (e.g. 1h)
 *
 * TimestampThresholds are especially used to scan command line input,
 * whereby nm is internally stored as n*60. The supported factors are
 * from s=1 over m=60 and h=60*60 up to Y=60*60*24*365. Beside this minor
 * difference, TimestampThreshold behaves as it's base class AbsoluteThreshold
 * (which is finally an Threshold<unsigned long long>).
 */
class TimestampThreshold
    : public AbsoluteThreshold
{
public:
    /**
     * default constructor - creates empty TimestampThreshold
     */
    TimestampThreshold()
        : AbsoluteThreshold()
    {}

    /**
     * constructor from value
     *
     * @param v - the initial value for this threshold
     */
    TimestampThreshold(unsigned long long const &v)
        : AbsoluteThreshold(v)
    {}

    /**
     * copy constructor
     *
     * @param r - reference to initialize this instance from
     */
    TimestampThreshold(TimestampThreshold const &r)
        : AbsoluteThreshold(r)
    {}

    /**
     * conversion constructor from base class
     *
     * @param r - reference to initialize this instance from
     */
    TimestampThreshold(Threshold<double> const &r)
        : AbsoluteThreshold(r)
    {}

    /**
     * assignment operator
     *
     * @param r - reference of another threshold to assign it to this one
     *
     * @return reference to this instance
     */
    inline TimestampThreshold & operator = (TimestampThreshold const &r) { AbsoluteThreshold::operator = (r); return *this; }
};

/**
 * Overload the 'validate' function for the TimestampThreshold class.
 * It makes sure that value is either an integer value with
 * optional multiplier extension (m=60, h=3600, {d,w,M,Y}=...) */
void validate(boost::any &v, 
              const std::vector<std::string> &values,
              TimestampThreshold *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);
    string::const_iterator se = s.end();

    unsigned long long multiplier = 1;

    if( !isdigit(s[s.length() - 1]) )
    {
        switch( s[s.length() - 1] )
        {
        case 's':
            break;

        case 'm':
            multiplier = 60;
            break;

        case 'h':
            multiplier = 60 * 60;
            break;

        case 'd':
            multiplier = 60 * 60 * 24;
            break;

        case 'w':
            multiplier = 60 * 60 * 24 * 7;
            break;

        case 'M':
            multiplier = 60 * 60 * 24 * 31;
            break;

        case 'Y':
            multiplier = 60 * 60 * 24 * 365;
            break;

        default:
            throw validation_error(validation_error::invalid_option_value, s);
        }
        --se;
    }

    v = any( TimestampThreshold( time(NULL) - ( lexical_cast<unsigned long long>( string( s.begin(), se ) ) * multiplier ) ) );
}

template < class T >
class RangeThreshold
    : public boost::tuple< T, T >
{
public:

    /**
     * constructor - constructs a non-empty range threshold with min and max
     *
     * @param min - the value for the min threshold
     * @param max - the value for the max threshold
     */
    RangeThreshold( T const &min = T(), T const &max = T(), bool negate = false )
        : boost::tuple< T, T >( min, max )
        , mNegate( negate )
    {}

    T const & getThresholdMin() const { return this->get<0>(); }
    T const & getThresholdMax() const { return this->get<1>(); }

    bool hasThresholdMin() const { return !this->get<0>().empty(); }
    bool hasThresholdMax() const { return !this->get<1>().empty(); }

    bool isNegated() const { return mNegate; }

protected:
    bool mNegate;
};


template<class T>
std::string
to_string(RangeThreshold<T> const &t)
{
    T min = t.getThresholdMin();
    T max = t.getThresholdMax();
    string s;
    if( t.hasThresholdMin() )
        s += to_string( t.getThresholdMin() );
    s += ":";
    if( t.hasThresholdMax() )
        s += to_string( t.getThresholdMax() );
    return s;
}

/**
 * Overload the 'validate' function for the RangeThreshold class.
 */
template< class T >
void validate(boost::any &v,
              const std::vector<std::string> &values,
              RangeThreshold<T> *, int)
{
    // Make sure no previous assignment to 'v' was made.
    validators::check_first_occurrence(v);
    // Extract the first string from 'values'. If there is more than
    // one string, it's an error, and exception will be thrown.
    string const &s = validators::get_single_string(values);

    string::size_type sb, st = 0;

    T min, max;
    bool minRead = false;
    bool maxRead = false;
    bool negated = false;

    while( st != string::npos )
    {
        boost::any tmp;

        st = s.find( ':', sb = st );

        string stmp( s, sb, st - sb );
        vector<string> vs;
        vs.push_back( stmp );

        if ( st != string::npos )
        {
            ++st;
        }

        if( ! minRead )
        {
            if ( ! stmp.empty() )
            {
                validate( tmp, vs, &min, 0);
                min = any_cast<T>(tmp);
            }
            minRead = true;
//            cout << "got min: " << to_string( min ) << endl;
            continue;
        }

        if( ! maxRead )
        {
            if ( ! stmp.empty() )
            {
                validate( tmp, vs, &max, 0);
                max = any_cast<T>(tmp);
            }
            maxRead = true;
//            cout << "got max: " << to_string( max ) << endl;
            continue;
        }

        throw validation_error(validation_error::invalid_option_value, s);
    }

    // if only single value is given this is interpreted as "up to <x>"
    //
    if ( minRead && ! maxRead )
    {
        max = min;
        min = T();
    }

    // now check if min > max, if so RangeCompares are negated
    // this only applies if both min and max are not empty
    //
    if ( !min.empty() && !max.empty() && min > max )
    {
        swap( min, max );
        negated = true;
    }

    v = any( RangeThreshold< T >( min, max, negated ) );
}



template < class T, class LoCmp = std::less< T >, class UpCmp = std::greater< T > >
class RangeCmp
    : public binary_function<RangeThreshold< T >, RangeThreshold< T >, bool>
{
public:
    /**
     * compare operator
     *
     * This operator returns true when:
     * - min value of x compared to min value of y using LoCmp returns true or
     * - max value of x compared to max value of y using UpCmp returns true or
     * - false in any other case
     *
     * - if y range is negated, return value is also negated
     *
     * When reading all this keep in mind that the "range" check for nagios
     * is somewhat strange. If you give a WARNING range an "OK" is expected
     * to be reported if the value to be proved lies within this range.
     * Thats why we have to return "false" when normally we would expect a "true" :)
     *
     * @param x - usually the determined range via snmp
     * @param y - usually the initiator specified range
     *
     * @return bool - true when x lies in y
     */
    inline bool operator () ( RangeThreshold< T > const &x, RangeThreshold< T > const &y ) const
    {
        bool rc = false;

        rc |= mLoCmp( x.getThresholdMin(), y.getThresholdMin() );
        rc |= mUpCmp( x.getThresholdMax(), y.getThresholdMax() );

        // negate assertion?
        //
        if ( y.isNegated() )
        {
            rc = ! rc;
        }

        return rc;
    }

protected:
    LoCmp mLoCmp;
    UpCmp mUpCmp;
};

#endif /* __SMART_SNMPD_NAGIOS_CHECKS_SNMP_CHECK_TYPES_H_INCLUDED__ */
