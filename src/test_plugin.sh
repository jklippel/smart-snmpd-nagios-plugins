#!/bin/sh

RC=$1
shift
OUT=`"$@" 2>&1`
CHK=$?

if [ $RC -ne $CHK ]
then
    echo "${OUT} [NOT OK: $RC != $CHK]"
else
    echo "${OUT} [OK]"
fi

exit 0
