#!/bin/bash
#
# Taken from my other repo https://github.com/nimpo/awsCrtSign
# and as such carries this LICENCE:
# <quote>
#
#    Copyright (C) 2020 Michael A S Jones <dr.mike.jones@gmail.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
###############################################################################
#
# If this program has been useful, you can show your appreciation by
# buying me a coffee: https://www.buymeacoffee.com/EmceeArsey
#
# </quote>
#
# The differences between that file and this are that all signing is done locally
# This produces an x509 v3 Certificate without openssl sanity checks against schema,
# e.g. Can have overly long RDNs such commonName > 64bytes, Country > 2bytes...

[ -e "test.key" ] || openssl genrsa -out test.key 512

E=`openssl rsa -in test.key -noout -text |grep publicExponent |sed -e 's/publicExponent: .*(\(0x[0-9a-f]*\)).*/\1/'`
M=`openssl rsa -in test.key -noout -modulus |grep '^Modulus=' |sed -e 's/^Modulus=/0x/'`
echo "$E" |grep -q '^0x[0-9A-F]\{1,\}$' || exit 4
echo "$M" |grep -q '^0x[0-9A-F]\{128,\}$' || exit 5

cat<<EOF > tbscertificate.asn1conf
asn1=SEQUENCE:tbscertificate

[signedcertificate]
tbscertificate=SEQUENCE:tbscertificate
alg=SEQUENCE:signature
signature=FORMAT:HEX,BITSTRING:rsasha256signature

[tbscertificate]
version=EXPLICIT:0C,INTEGER:0x02
serialNo=INTEGER:0x02
signature=SEQUENCE:signature
issuer=SEQUENCE:issuer
validity=SEQUENCE:validity
subject=SEQUENCE:issuer
SPKI=SEQUENCE:SPKI
extensions=EXPLICIT:3C,SEQUENCE:v3ext

[signature]
algorithm=OID:sha256WithRSAEncryption
parameter=NULL
#Obvs anachronistic!

[issuer]
c=SET:cseq
st=SET:stseq
l=SET:lseq
o=SET:oseq
ou=SET:ouseq
cn=SET:cnseq
email=SET:eseq

[cseq]
rdn=SEQUENCE:country

[country]
o=OID:countryName
v=PRINTABLESTRING:GB

[stseq]
rdn=SEQUENCE:stateorprovince

[stateorprovince]
o=OID:stateOrProvinceName
v=PRINTABLESTRING:Cottingshire

[lseq]
rdn=SEQUENCE:locality

[locality]
o=OID:localityName
v=PRINTABLESTRING:Cottington

[oseq]
rdn=SEQUENCE:organisation

[organisation]
o=OID:organizationName
v=PRINTABLESTRING:Cottingshire County Council

[ouseq]
rdn=SEQUENCE:organisationalunit

[organisationalunit]
o=OID:organizationalUnitName
v=PRINTABLESTRING:Planning Office

[cnseq]
rdn=SEQUENCE:commonname

[commonname]
o=OID:commonName
v=PRINTABLESTRING:The Bottom of the Locked Filing Cabinet Stuck In The Disused Lavatory With A Sign On The Door Saying Beware Of The Leopard In The Unlit Cellar Of The Cottingshire County Council Planning Office With No Stairs

[eseq]
rdn=SEQUENCE:email

[email]
o=OID:emailAddress
v=IA5STRING:Cottingshire.County.Council.Planning@mike-jones.uk

[validity]
#YYMMDDHHMMSSZ
b=UTCTIME:820606080000Z
a=UTCTIME:821004110000Z

[SPKI]
algorithm=SEQUENCE:RSAEnc
pubkey=BITWRAP,SEQUENCE:rsapubkey

[RSAEnc]
algorithm=OID:rsaEncryption
parameter=NULL

[rsapubkey]
n=INTEGER:$M
e=INTEGER:$E

[v3ext]
basicConstraints = SEQUENCE:basicConstraints
keyUsage = SEQUENCE:keyUsage
extendedKeyUsage = SEQUENCE:extendedKeyUsage 
issuerAltName = SEQUENCE:issuerAltName

[basicConstraints]
o=OID:basicConstraints
v=FORMAT:HEX,OCTETSTRING:3000

[keyUsage]
o=OID:keyUsage
v=FORMAT:HEX,OCTETSTRING:030204B0

[extendedKeyUsage]
o=OID:extendedKeyUsage
v=FORMAT:HEX,OCTETSTRING:301406082B0601050507030106082B06010505070302

[issuerAltName]
o=OID:issuerAltName
v=OCTWRAP,SEQUENCE:ian

[ian]
i=FORMAT:ASCII,IMPLICIT:1C,OCTETSTRING:Cottingshire.County.Council.Planning@mike-jones.uk

[signaturedata]
alg=SEQUENCE:signature
signature=FORMAT:HEX,BITSTRING:rsasha256signature
EOF

# Use above template to generate a TBSCertificate in DER (binary format)
openssl asn1parse -genconf tbscertificate.asn1conf -noout -out - > tbscertificate.der || exit 7

# Create a binary SHA256 digest of TBSCertificate file
openssl sha256 -binary -out tbscertificate.sha256 tbscertificate.der || exit 8

# Use RSA to "sign" that binary SHA256 digets
openssl pkeyutl -sign -in tbscertificate.sha256 -inkey test.key -out tbscertificate.sha256.sig || exit 9

# Pull in as a hex string into the variable SIGNATURE and check it looks ok
SIGNATURE=`od -tx1 -An -v -w1 tbscertificate.sha256.sig |tr -d ' \n' |tr a-f A-F`
echo $SIGNATURE |grep -q '^[0-9A-F]\{1,\}$' || exit 10

# Alter the configuration file above such that the SIGNATURE is added to the [signedcertificate] stanza.
# and that the output: "asn1", is updated to be a SEQUENCE of that signedcertificate which is
# a {tbscertificate + alg + signature} i.e. it will produce an x.509 (v2 in this case) certificate
sed -i "s/:rsasha256signature$/:$SIGNATURE/" tbscertificate.asn1conf

sed -i "s/^asn1=SEQUENCE:tbscertificate$/asn1=SEQUENCE:signedcertificate/" tbscertificate.asn1conf

openssl asn1parse -genconf tbscertificate.asn1conf -noout -out - > signedcertificate.der || exit 11

openssl x509 -inform DER -in signedcertificate.der -out signedcertificate.crt || exit 12

