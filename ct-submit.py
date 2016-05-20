#!/usr/bin/env python2
# encoding=utf-8
from __future__ import print_function, with_statement
import os
import sys
import re
import json
import urllib2
import struct
import zipfile
import StringIO

post_urls = [
    'https://ct.googleapis.com/aviator',
    'https://ct.googleapis.com/pilot',
    'https://ct.googleapis.com/rocketeer',
    'https://log.certly.io',
    'https://ct1.digicert-ct.com/log',
    'https://ct.izenpe.com'
]


class Pem:
    pattern = re.compile(
            r"-----BEGIN (\w+)-----([^-]+)-----END \1-----", re.MULTILINE)

    class Cert:
        CERTIFICATE = 'CERTIFICATE'

        def __init__(self, type, body):
            self.kind = type
            self.body = body

        def __str__(self):
            return "Type:%s\nBody:%s" % (self.kind, self.body)

    def __init__(self):
        self.certs = []

    def parse(self, pem_str):
        for i in Pem.pattern.finditer(pem_str):
            self.certs.append(
                    Pem.Cert(i.group(1), i.group(2).replace('\n', '')))

    def parse_file(self, filename):
        with open(filename) as pem_file:
            self.parse(pem_file.read())

    def __iter__(self):
        return iter(self.certs)


def post(url, data):
    request = urllib2.Request(url, data, {'Content-Type': '"application/json"'})
    req = urllib2.urlopen(request)
    if req is not None and req.getcode() == 200:
        return req.read()
    else:
        raise IOError("response code is not 200")


def encrypt(payload):
    encrypted = StringIO.StringIO()
    encrypted.write(struct.pack('!B', payload['sct_version']))
    encrypted.write(payload['id'].decode('base64'))
    encrypted.write(struct.pack("!q", payload['timestamp']))
    ext = payload['extensions'].decode('base64')
    if len(ext) > 65535:
        raise Exception("Extensions too long")
    else:
        encrypted.write(struct.pack('!H', len(ext)))
        encrypted.write(ext)
        encrypted.write(payload['signature'].decode('base64'))
    return encrypted.getvalue()


def enc_url(url):
    return url.replace('https://', '').replace('/', '').replace('.', '').replace('-', '')


def main(filename, output_zip=False):
    pem = Pem()
    pem.parse_file(filename)
    chains = {'chain': []}
    for i in pem:
        if i.kind == Pem.Cert.CERTIFICATE:
            chains['chain'].append(i.body)
    chains_str = json.dumps(chains)
    output = None
    if output_zip:
        output = zipfile.ZipFile(
                os.path.splitext(filename)[0] + '.zip', "w", zipfile.ZIP_DEFLATED)

    for url in post_urls:
        print("request: %s" % url)
        try:
            payload = json.loads(post(url + '/ct/v1/add-chain', chains_str))
            if output_zip:
                output.writestr(enc_url(url) + '.sct', encrypt(payload))
            else:
                with open(enc_url(url) + '.sct', 'w') as f:
                    f.write(encrypt(payload))
        except Exception as e:
            print("failed:  %s\n%s" % (url, e))
    if output_zip:
        output.close()
    print('finished')


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print(
                'Usage: %s <pem filename> [-z]\nct-submit is a helper to get certificate transparency timestamp\n| -z: generate a zip file' %
                sys.argv[0])
    else:
        if os.access(sys.argv[1], os.R_OK):
            main(sys.argv[1], sys.argv.count('-z') == 1)
        else:
            print('%s can not read or not found' % sys.argv[1])
