#!/bin/bash
# call this script with an email address (valid or not).
# must install openssl before run this script.
# like:
# ./makecert.sh demo@random.com

#TODO should be add "subjectAltNames"

rm -f server.pem server.key client.pem client.key

SUBJECT="/C=CN/ST=Shanghai/L=Earth/O=/OU=/CN=/emailAddress"

EMAIL=${1:-develop@example.com}
DAYS=${2:-36500}

echo "make server cert"
openssl req -new -nodes -x509 -out server.pem -keyout server.key -days ${DAYS} -subj "${SUBJECT}=${EMAIL}"
openssl x509 -outform der -in server.pem -out server.der

echo "make client cert"
openssl req -new -nodes -x509 -out client.pem -keyout client.key -days ${DAYS} -subj "${SUBJECT}=${EMAIL}"

openssl pkcs12 -export -clcerts -inkey client.key -passin pass: -password pass:  -in client.pem -out client.p12