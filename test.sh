#!/usr/bin/env bash

TEST=0
for CERT in testCerts/*.pem 
do 
  OPENSSLHASH=`openssl x509 -in $CERT -noout -subject_hash 2>/dev/null`
  HASHBASHSSL=`./hash-bash-ssl.sh $CERT 2>/dev/null`
  MSG="[ FAIL ]"
  [ "$HASHBASHSSL" -a "$OPENSSLHASH" = "$HASHBASHSSL" ] && MSG="[  OK  ]" || TEST=1
  printf "%-40s %8s == %8s %s\n" "$CERT" "$OPENSSLHASH" "$HASHBASHSSL" "$MSG"
done
exit $TEST
