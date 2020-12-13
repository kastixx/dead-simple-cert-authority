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

    def __init__(self, basename, cert_dir=None, key_dir=None):
        self.cert_dir = cert_dir or os.path.abspath(os.curdir)
        self.key_dir = key_dir or cert_dir
        self.basename = basename

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

    @property
    def certificate_path(self):
        return os.path.join(self.cert_dir, self.basename + self.CERT_SUFFIX)

    @property
    def private_key_path(self):
        return os.path.join(self.key_dir, self.basename + self.KEY_SUFFIX)

    @property
    def rsa_private_key_path(self):
        return os.path.join(self.key_dir, self.basename + self.RSA_KEY_SUFFIX)

    @property
    def request_path(self):
        return os.path.join(self.cert_dir, self.basename + self.REQUEST_SUFFIX)

    def store(self, with_request=False, require_rsa=False):
        certificate = self.require_certificate
        with open(self.certificate_path, 'wt') as fd:
            fd.write(certificate)

        private_key = self.require_private_key
        with open(self.private_key_path, 'wt') as fd:
            fd.write(private_key)

        if require_rsa:
            rsa_private_key = self.require_rsa_private_key
        else:
            rsa_private_key = self.rsa_private_key
        if rsa_private_key:
            with open(self.rsa_private_key_path, 'wt') as fd:
                fd.write(rsa_private_key)

        if with_request:
            request = self.require_request
            with open(self.request_path, 'wt') as fd:
                fd.write(request)

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
