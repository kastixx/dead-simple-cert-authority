__all__ = [ 'Context' ]

import re
import os

class Context:
    RE_PARSE_FENCED = re.compile('(.*?)-----BEGIN\\s(.+?)-----\n.*?-----END\\s(.+?)-----\n', re.S)
    CERT_SUFFIX = '.pem'
    KEY_SUFFIX = '.key'
    RSA_KEY_SUFFIX = '.rsa'
    REQUEST_SUFFIX = '.req'

    def parse_fenced_output(self, output):
        parts = []
        outside = []
        for m in self.RE_PARSE_FENCED.finditer(output):
            full_match = m.group(0)
            outside_part, begin_part, end_part = m.groups()
            if begin_part != end_part:
                raise Exception('begin/end mismatch: "{}" != "{}"'.format(begin_part, end_part))
            parts.append((begin_part, full_match))
            outside.append(outside_part)

        return parts, ''.join(outside)

    certificate = None
    private_key = None
    rsa_private_key = None
    request = None
    ca_certificates = None

    def __init__(self, basename, ca_context=None, is_ca=False):
        self.basename = basename
        self.ca_context = ca_context
        self.is_ca = is_ca

    def add(self, output):
        parts, outside = self.parse_fenced_output(output)
        for key, part in parts:
            if key == 'CERTIFICATE':
                self.certificate = part
            elif key == 'PRIVATE KEY':
                self.private_key = part
            elif key == 'CERTIFICATE REQUEST':
                self.request = part
            elif key == 'RSA PRIVATE KEY':
                self.rsa_private_key = part
            else:
                raise Exception("unknown part {}".format(key))

        return outside

    def add_from_file(self, path):
        with open(path, 'rt') as fd:
            self.add(fd.read())

    @property
    def require_private_key(self):
        if self.private_key is None:
            raise Exception("Missing private key")
        return self.private_key

    @property
    def require_certificate(self):
        if self.certificate is None:
            raise Exception("Missing certificate")
        return self.certificate

    @property
    def require_rsa_private_key(self):
        if self.rsa_private_key is None:
            raise Exception("Missing RSA private key")
        return self.rsa_private_key

    @property
    def require_request(self):
        if self.request is None:
            raise Exception("Missing request")
        return self.request
