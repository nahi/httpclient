#!/bin/sh

if ! test -d ./lib/httpclient; then
    echo missing lib/httpclient directory
    exit 1
fi

NOW=$(date)
cat <<EOF >lib/httpclient/cacert.pem
##
## Bundle of CA Root Certificates
##
## Certificate data from Mozilla as of: $NOW
##
## This is a bundle of X.509 certificates of public Certificate Authorities
## (CA). These were automatically extracted from Mozilla's root certificates
## file (certdata.txt).  This file can be found in the mozilla source tree:
## http://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt
##
## It contains the certificates in PEM format and therefore
## can be directly used with curl / libcurl / php_curl, or with
## an Apache+mod_ssl webserver for SSL client authentication.
## Just configure this file as the SSLCACertificateFile.

EOF

find /usr/share/ca-certificates/mozilla/ -type f -name '*.crt' \
    | while read f
	do
	    name=`basename $f | sed -e 's|_| |g' -e 's|\.crt||'`
	    echo
	    echo $name
	    echo $name | sed 's|.|=|g'
	    cat $f
	done >>lib/httpclient/cacert.pem

exit $?
