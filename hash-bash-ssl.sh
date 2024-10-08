#!/bin/bash

# BASH-ish way to get new (for old values of new) OpenSSL sha1-based subject name hash. This code should produce the same as current
# openssl <$1> x509 -noout -hash
# Here I'm using GNU's sed and awk mileage with other awks ans seds may vary

# Some notes: The "hash" is essentially a dump of the certificate's DER encoded subjectname SEQUENCE with the following modifications:
# 1, the leading SEQUENCE header is stripped that's the first \x30\xXX((\xXX>7e?\xYY{\xXX}:"") i.e. between 2 and 258 bytes.
# 2, Strings encoded as PRINTABLESTRING, IA5STRING, T61String (...) become UTF8 strings. NB I've assumed openssl's -nameopt utf8 has converted data to utf8 and have therefore just updated the corresponding headers
# 3, the Strings also become lowercase, have leading and trailing spaces removed and duplicate spaces collapsed

# Written for giggles by Mike Jones mike-jones.uk

function encOID () { #returns HEX BER OID e.g. echo "2.5.4.3" | encOID -> 550403
  awk -F. '{printf("%02x",$1*40+$2);for(i=3;i<=NF;i++){a=$i;s="";while(a>0){b=a%128;a-=b;a/=128;s=sprintf("%02x%s",(s!=""?b+128:b),s);}printf(s)}}'
}

function ASN1wrap () { # returns HEX BER ASN1Tag.ASN1Len.<stdin>; e.g. echo "550403" | ASN1wrap 06 -> 0603550403 ; 06=OID 0c=UTF8String 30=SEQUENCE 31=SET
  awk -v t="$1" '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256)+128,l);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("%s%s%s",t,lh,$1)}'
}
function ASN1wrap () { # returns HEX BER ASN1Tag.ASN1Len.<stdin>; e.g. echo "550403" | ASN1wrap 06 -> 0603550403 ; 06=OID 0c=UTF8String 30=SEQUENCE 31=SET
  awk -v t="$1" '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256)+128,l);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("%s%s%s\n",t,lh,$1)}'
}

function tolower () { # Not sure if OSSL converts all UTF8 upper to lower (does e.g. Ĥ -> ĥ ?) but a quick eyeball of the code shows case_change to lower case is defined along the lines of: c=ifupper(c)?(c^\0x40);
                      # Also we'll ignore RDNs > 65535 bytes long (I've never come across one > 127; while one might generate such a large one, I think most clients would break.)
                      # e.g. echo 0c0d4d696b652d4a6f6e65732e756B | tolower -> 0c0d6d696b652d6a6f6e65732e756B ( i.e. UTF8String(Mike-Jones.uk) -> UTF8String(mike-jones.uk) )
  sed -e 's/\(..\)/\1 /g' -e 's/^\(..\) \([0-7].\|80\)/\1\2/' -e 's/^\(..\) \(81\) \(..\)/\1\2\3/' -e 's/^\(..\) \(82\) \(..\) \(..\)/\1\2\3\4/' -e 's/ 4\([1-9a-fA-F]\)/6\1/ig' -e 's/5\([0-9aA]\)/7\1/ig' -e 's/ //g'
}

function stripspace () { # Remove leading and trailingspace; convert and deduplicate duplicate remaining spaces to \x20
                         # OSSL defines these as "CTYPE_MASK_space"= {\t\n\v\f\r\x20} + {\b} :- 08 09 0a 0b 0c 0d 20
  sed -e 's/\(..\)/\1 /g' -e 's/^\(..\) \([0-7].\|80\)/\1\2/' -e 's/^\(..\) \(81\) \(..\)/\1\2\3/' -e 's/^\(..\) \(82\) \(..\) \(..\)/\1\2\3\4/' -e 's/ \(20\|08\|09\|0[aA]\|0[bB]\|0[cC]\|0[dD]\|20\)/ 20/g' -e 's/\( 20\)\{2,\}/ 20/g' -e 's/^\(..[0-7].\|..80\|..81..\|..82....\)\( 20\)\{1,\}/\1/' -e 's/\( 20\)\{1,\} *$//' -e 's/ //g' -e 's/^\(..\)\([0-7].\|80\|81..\|82....\)/\1 \2 /' | while read type len data ; do echo $data | ASN1wrap $type ; done
}

function hextochar () {
  sed -e 's/\(..\)/\\\\x\1/g' |xargs -i echo -ne '{}'
}

function digest() {

  if [ "$1" = "y" ] 
  then
    md5sum 
  else
    sha1sum
  fi
}

# Function to unwrap ASN1
function getContents() { # Reads Hex String, ignores Tag (assuming Tag < 32 ie tag header is 1 byte); figures out length of content; returns content; "$1"="" or "$1"=0 return all 
  awk -v n="$1" -v v="$2" 'BEGIN {for(i=0;i<16;i++){x[sprintf("%x",i)]=i}}
  {
    s=$0;
    m=0;
    while ( length(s) > 0 ) {
      m++;
      if(x[substr(s,3,1)]>7){
        llh=sprintf("%i",(x[substr(s,3,1)]*16)+x[substr(s,4,1)]-128);     # Length of length header contents: 3rd and 4th nibble of input & 0x01111111 converted to decimal 1-127
        if (llh==0) {print "!! undefined length - 0000 terminated ASN1 objects, are not supported!!"}
        lh=substr(s,5,llh*2);                                             # string length of llh in nibbles starting at 5th nibble
        split(lh,ln,"");                                                 # split header into array of nibbles
        li=0
        for(c=1;c<=length(lh);c++) { li*=16; li+=x[ln[c]]}                # loop through nibbles as c starting with least significant: li = li<<4 + DEC-value-of-that-nibble ; Should return int of byte length
        if(n==m||!n)print (v?substr(s,1,2):"") (v?" ":"") substr(s,1+2+2+(2*llh),li*2);   # contents start at 1 + 2(taglen) + 2(headlendesc) + (length of header in bytes) * 2
        s=substr(s,1+2+2+(2*llh)+li*2)
      }else{
        li=sprintf("%i",(x[substr(s,3,1)]*16)+x[substr(s,4,1)]);
        if(n==m||!n)print (v?substr(s,1,2):"") (v?" ":"") substr(s,5,li*2);             # TAG(2n) Lenght(2n) Then content of li*2 nibles
        s=substr(s,1+2+2+(li*2))
      }
    }
  }'
}

function getSubject() { # Reads in HEX string and finds Subject DN and spits out inner HEX string Assuming an X.509
  getContents |getContents 1 | sed -e 's/a003020102//' |getContents 5
}

function getIssuer() { # Reads in HEX string and finds Subject DN and spits out inner HEX string Assuming an X.509
  getContents |getContents 1 | sed -e 's/a003020102//' |getContents 3
}

function canonicalizeDN() {
  getContents | getContents | getContents 0 -v| sed -e 's/\([0-9a-f]\{2\}\)/\1 /g' |awk '/^(13|14|16|0c)/ {gsub(/(08|09|0a|0b|0c|0d)/,"20"); $1="0c "; gsub (/^0c  (20 )*/,"0c  "); gsub(/(20 ?)+/,"20 "); gsub(/(20) *$/,""); print } !/^(13|14|16|0c)/ {print}' |while read tag content 
  do 
    if [ "$tag" = "0c" ]
    then
      echo $content |sed -e 's/4\([1-9a-f]\)/6\1/g' -e 's/5\([0-9a]\)/7\1/g' |tr -d ' ' | ASN1wrap $tag
    else
      echo $content |tr -d ' ' | ASN1wrap $tag
    fi
  done | sed '$!N;s/\n//' | ASN1wrap 30 | ASN1wrap 31 |tr -d '\n'
}

# Function to turn PEM into DER
function getDERfromPEM () { #Returns HEX encoded DER of first PEM Certificate in file 
  awk '/^-----BEGIN CERTIFICATE-----$/ {i=1} /^[A-Za-z0-9\/+=]+\r?$/ { if(i) print } /-----END CERTIFICATE-----/ {exit }' |tr -d '\r\n' |base64 -d |od -An -v -w0 -tx1 2>/dev/null |grep '^[0-9a-f ]*$' |tr -d "\n "
}

[ "$1" = "-old" ] && OLD="y" && shift
## First use openssl to do most of the leg work; spit the subject out with as much BER work done for us as possible
#openssl x509 -in "$1" -subject -noout -nameopt multiline,utf8,dump_der,dump_all,oid |grep '^[[:space:]]*[0-9]' | while read oid e str
#do
#  if [ "$OLD" = "y" ]
#  then
#    ( echo "$oid" | encOID | ASN1wrap "06" ; echo "$str" | sed -e 's/#//' )
#  else
#    ( echo "$oid" | encOID | ASN1wrap "06" ; echo "$str" | sed -e 's/#//' -e 's/^\(13\|14\|16\)/0c/' |tolower| stripspace )
#  fi
#done | sed '$!N;s/\n//' | ASN1wrap 30 | ASN1wrap 31 | tr -d '\n' | ( [ "$OLD" = "y" ] && ASN1wrap "30" || cat ) | hextochar |digest "$OLD" |sed -e 's/\(..\)\(..\)\(..\)\(..\).*/\4\3\2\1/'

cat "$1" | getDERfromPEM | getSubject | ( [ "$OLD" = "y" ] && ASN1wrap "30" ||  canonicalizeDN ) | hextochar |digest "$OLD" |sed -e 's/\(..\)\(..\)\(..\)\(..\).*/\4\3\2\1/'
#cat "$1" | getDERfromPEM | getIssuer | canonicalizeDN | hextochar |digest "$OLD" |sed -e 's/\(..\)\(..\)\(..\)\(..\).*/\4\3\2\1/'

# Oneline? -- not updated for recent changes!
# openssl x509 -in $PATHTOCERT.pem -subject -noout -nameopt multiline,utf8,dump_der,dump_all,oid |grep '^[[:space:]]*[0-9]' | while read oid e str ; do echo -ne `( echo $oid | awk -F. '{printf("%02x",$1*40+$2);for(i=3;i<=NF;i++){a=$i;while(a>0){b=a%128;a-=b;a/=128;printf("%02x",(a>0?b+128:b));}}}' | awk '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("06%s%s",lh,$1)}' ; echo "$str" | sed -e 's/#//' -e 's/^\(13\|14\|16\)/0c/' | sed -e 's/\(..\)/\1 /g' -e 's/^\(..\) \([0-7].\|80\)/\1\2/' -e 's/^\(..\) \(81\) \(..\)/\1\2\3/' -e 's/^\(..\) \(82\) \(..\) \(..\)/\1\2\3\4/' -e 's/ 4\([1-9a-fA-F]\)/6\1/ig' -e 's/5\([0-9aA]\)/7\1/ig' -e 's/ //g' | sed -e 's/\(..\)/\1 /g' -e 's/^\(..\) \([0-7].\|80\)/\1\2/' -e 's/^\(..\) \(81\) \(..\)/\1\2\3/' -e 's/^\(..\) \(82\) \(..\) \(..\)/\1\2\3\4/' -e 's/ \(20\|08\|09\|0[aA]\|0[bB]\|0[cC]\|0[dD]\|20\)/ 20/g' -e 's/\( 20\)\{2,\}/ 20/g' -e 's/^\(....\)\( 20\)\{1,\}/\1/' -e 's/\( 20\)\{1,\} *$//' -e 's/ //g' -e 's/\(..\)\(..\)/\1 \2 /' | while read type len data ; do echo $data | awk -v t="$type" '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("%s%s%s",t,lh,$1)}' ; done )|awk '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("30%s%s",lh,$1)}'|awk '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("31%s%s",lh,$1)}' | sed -e 's/\(..\)/\\\x\\1/g'` ; done | sha1sum | sed -e 's/\(..\)\(..\)\(..\)\(..\).*/\4\3\2\1/'

