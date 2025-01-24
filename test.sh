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

echo "getDERfromPEM testCerts/utf8_only.pem and extract subject"
echo "Should see: "
echo "3112301006035504080c094775696c64666f72643130302e06035504070c27536f6d65776865726520696e2074686520766963696e697479206f6620426574656c676575736531273025060355040a0c1e5369726975732043796265726e657469637320436f72706f726174696f6e311d301b060355040b0c144d61726b6574696e67204465706172746d656e743121301f06035504030c18436f6c696e2074686520536563757269747920526f626f74"

cat testCerts/utf8_only.pem | gawk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) printf("%s",$0) } /-----END CERTIFICATE-----/ {exit }' |base64 -d | od -tx1 -An -w99999999 |tr -d ' ' | getSubject

echo END




exit $TEST
