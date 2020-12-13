#!/bin/sh

openssl req \
    -config - \
    -days 3650 \
    -x509
