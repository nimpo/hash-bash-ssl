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
  awk -F. '{printf("%02x",$1*40+$2);for(i=3;i<=NF;i++){a=$i;while(a>0){b=a%128;a-=b;a/=128;printf("%02x",(a>0?b+128:b));}}}'
}

function ASN1wrap () { # returns HEX BER ASN1Tag.ASN1Len.<stdin>; e.g. echo "550403" | ASN1wrap 06 -> 0603550403 ; 06=OID 0c=UTF8String 30=SEQUENCE 31=SET
  awk -v t="$1" '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256)+128,l);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("%s%s%s",t,lh,$1)}'
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

# First use openssl to do most of the leg work; spit the subject out with as much BER work done for us as possible
openssl x509 -in "$1" -subject -noout -nameopt multiline,utf8,dump_der,dump_all,oid |grep '^[[:space:]]*[0-9]' | while read oid e str
do
  ( echo "$oid" | encOID | ASN1wrap "06" ; echo "$str" | sed -e 's/#//' -e 's/^\(13\|14\|16\)/0c/' |tolower| stripspace ) | ASN1wrap "30" |ASN1wrap "31" | hextochar
done |sha1sum |sed -e 's/\(..\)\(..\)\(..\)\(..\).*/\4\3\2\1/'


# Oneline?
# openssl x509 -in $PATHTOCERT.pem -subject -noout -nameopt multiline,utf8,dump_der,dump_all,oid |grep '^[[:space:]]*[0-9]' | while read oid e str ; do echo -ne `( echo $oid | awk -F. '{printf("%02x",$1*40+$2);for(i=3;i<=NF;i++){a=$i;while(a>0){b=a%128;a-=b;a/=128;printf("%02x",(a>0?b+128:b));}}}' | awk '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("06%s%s",lh,$1)}' ; echo "$str" | sed -e 's/#//' -e 's/^\(13\|14\|16\)/0c/' | sed -e 's/\(..\)/\1 /g' -e 's/^\(..\) \([0-7].\|80\)/\1\2/' -e 's/^\(..\) \(81\) \(..\)/\1\2\3/' -e 's/^\(..\) \(82\) \(..\) \(..\)/\1\2\3\4/' -e 's/ 4\([1-9a-fA-F]\)/6\1/ig' -e 's/5\([0-9aA]\)/7\1/ig' -e 's/ //g' | sed -e 's/\(..\)/\1 /g' -e 's/^\(..\) \([0-7].\|80\)/\1\2/' -e 's/^\(..\) \(81\) \(..\)/\1\2\3/' -e 's/^\(..\) \(82\) \(..\) \(..\)/\1\2\3\4/' -e 's/ \(20\|08\|09\|0[aA]\|0[bB]\|0[cC]\|0[dD]\|20\)/ 20/g' -e 's/\( 20\)\{2,\}/ 20/g' -e 's/^\(....\)\( 20\)\{1,\}/\1/' -e 's/\( 20\)\{1,\} *$//' -e 's/ //g' -e 's/\(..\)\(..\)/\1 \2 /' | while read type len data ; do echo $data | awk -v t="$type" '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("%s%s%s",t,lh,$1)}' ; done )|awk '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("30%s%s",lh,$1)}'|awk '{l=length($1)/2;if(l<128){lh=sprintf("%02x",l)}else{lh=sprintf("%02x%x",int((l+256)/256),l);printf(lh);if(length(lh)%2==1)sub(/^../,"&0",lh)}printf("31%s%s",lh,$1)}' | sed -e 's/\(..\)/\\\x\\1/g'` ; done | sha1sum | sed -e 's/\(..\)\(..\)\(..\)\(..\).*/\4\3\2\1/'

