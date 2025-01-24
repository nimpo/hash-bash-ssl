#!/usr/bin/env bash

TEST=0

gawk --version
sed --version
md5sum --version
sha1sum --version

for CERT in testCerts/*.pem 
do 
  OPENSSLHASH=`openssl x509 -in $CERT -noout -subject_hash # 2>/dev/null`
  HASHBASHSSL=`./hash-bash-ssl.sh $CERT # 2>/dev/null`
  MSG="[ FAIL ]"
  [ "$HASHBASHSSL" -a "$OPENSSLHASH" = "$HASHBASHSSL" ] && MSG="[  OK  ]" || TEST=1
  printf "SUBJECT NEW %-40s %8s == %8s %s\n" "$CERT" "$OPENSSLHASH" "$HASHBASHSSL" "$MSG"
  OPENSSLHASH=`openssl x509 -in $CERT -noout -subject_hash_old 2>/dev/null`
  HASHBASHSSL=`./hash-bash-ssl.sh -old $CERT 2>/dev/null`
  MSG="[ FAIL ]"
  [ "$HASHBASHSSL" -a "$OPENSSLHASH" = "$HASHBASHSSL" ] && MSG="[  OK  ]" || TEST=1
  printf "SUBJECT OLD %-40s %8s == %8s %s\n" "$CERT" "$OPENSSLHASH" "$HASHBASHSSL" "$MSG"
  OPENSSLHASH=`openssl x509 -in $CERT -noout -issuer_hash # 2>/dev/null`
  HASHBASHSSL=`./hash-bash-ssl.sh -issuer $CERT # 2>/dev/null`
  MSG="[ FAIL ]"
  [ "$HASHBASHSSL" -a "$OPENSSLHASH" = "$HASHBASHSSL" ] && MSG="[  OK  ]" || TEST=1
  printf "ISSUER  NEW %-40s %8s == %8s %s\n" "$CERT" "$OPENSSLHASH" "$HASHBASHSSL" "$MSG"
  OPENSSLHASH=`openssl x509 -in $CERT -noout -issuer_hash_old 2>/dev/null`
  HASHBASHSSL=`./hash-bash-ssl.sh -issuer -old $CERT 2>/dev/null`
  MSG="[ FAIL ]"
  [ "$HASHBASHSSL" -a "$OPENSSLHASH" = "$HASHBASHSSL" ] && MSG="[  OK  ]" || TEST=1
  printf "ISSUER  OLD %-40s %8s == %8s %s\n" "$CERT" "$OPENSSLHASH" "$HASHBASHSSL" "$MSG"
done

echo "Test by source"

. hash-bash-ssl.sh

echo 'echo "2.5.4.3" | encOID == 550403'
echo  "2.5.4.3" | encOID

echo 'echo "550403" | ASN1wrap 06 == 0603550403'
echo "550403" | ASN1wrap 06

echo 'echo "0c0d4d696b652d4a6f6e65732e756B" | tolower == 0c0d6d696b652d6a6f6e65732e756B'
echo "0c0d4d696b652d4a6f6e65732e756B" | tolower

echo 'echo "20205465737409206f662008207374726970737061636520" | stripspace == 54657374206f662073747269707370616365'
echo "20205465737409206f662008207374726970737061636520" | stripspace

echo 'echo 54657374206f6620686578746f63686172 | hextochar == "Test of hextochar"'
echo "54657374206f6620686578746f63686172" | hextochar
echo

echo 'echo "a003020101" | getContents == 020101'
echo "a003020101" | getContents

echo "Test openssl DER creation with getDERfromPEM"
echo -n "Test openssl: "
openssl x509 -outform DER -in testCerts/utf8_only.pem |od -tx1 |sed -e 's/[0-9]\{7\}//'

echo becomes:

openssl x509 -outform DER -in testCerts/utf8_only.pem |od -tx1 -w9999999 |sed -e 's/[0-9]\{7\}//' -e 's/ //g'
echo
echo -n "Test getDERfromPEM: "
cat testCerts/utf8_only.pem | getDERfromPEM
echo
echo extract PEM from cert
cat testCerts/utf8_only.pem | gawk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) print } /-----END CERTIFICATE-----/ {exit }'
echo
echo "Now remove CRLFs"
cat testCerts/utf8_only.pem | gawk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) print } /-----END CERTIFICATE-----/ {exit }' |tr -d '\r\n'
echo
echo Try someting to see if full cert is extracted

cat testCerts/utf8_only.pem | gawk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) printf("%s",$0) } /-----END CERTIFICATE-----/ {exit }' |base64 -d | od -tx1 -An -tx1 -w99999999 |tr -d " "

echo check lengths before removal of '\r\n' then after
cat testCerts/utf8_only.pem | gawk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) print } /-----END CERTIFICATE-----/ {exit }' |wc 
cat testCerts/utf8_only.pem | gawk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) print } /-----END CERTIFICATE-----/ {exit }' |tr -d '\r\n' |wc
echo 
echo 'echo "test base64 decode" | base64 | base64 -d == "test base64 decode"'
echo "test base64 decode" | base64 | base64 -d 

echo "Full Extract to DER hex"
cat testCerts/utf8_only.pem | gawk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) print } /-----END CERTIFICATE-----/ {exit }' |tr -d '\r\n' |base64 -d |od -An -v -w999999 -tx1 |tr -d "\n "
echo

#env
#
#echo Pipes are Lines are truncating at 1024 what is the config
#getconf -a 

dd bs=512 count=1 if=/dev/zero  | wc
dd bs=1024 count=1 if=/dev/zero  | wc
dd bs=2048 count=1 if=/dev/zero  | wc
dd bs=4096 count=1 if=/dev/zero  | wc

echo END




exit $TEST
