__all__ = [ 'OpenSSL' ]

import subprocess
import re

from .temporary import make_temp_file
from .certinfo import CertInfo

TIMEOUT = 30

class OpenSSL:
    binary = 'openssl'

    def __init__(self, binary=None):
        if binary is not None:
            self.binary = binary

    def run(self, args, input=None):
        try:
            proc = subprocess.run([self.binary, *args],
                    capture_output=True, check=True, text=True,
                    timeout=TIMEOUT, input=input)

        except subprocess.CalledProcessError as e:
            raise Exception('{}\nOutput:\n{}'.format(e, e.stderr))

        return proc.stdout

    def add_rsa_key(self, context):
        output = self.run(['rsa'], input=context.require_private_key)
        context.add(output)
        return context

    def request(self, context, request):
        cfg_text = request.config.generate
        tmp_path = make_temp_file(cfg_text)
        output = self.run(['req', '-new', '-config', tmp_path])
        context.add(output)
        return context, tmp_path

    def self_signed(self, context, request):
        cfg_text = request.config.generate
        output = self.run('req -x509 -config - -days {}'.format(request.days).split(), input=cfg_text)
        context.add(output)
        return context

    def signed(self, context, request, ca_paths):
        _, tmp_path = self.request(context, request)
        output = self.run([
            'x509', '-req', '-in', '-',
            '-CA', ca_paths.cert,
            '-CAkey', ca_paths.key,
            '-days', str(request.days),
            '-CAcreateserial',
            '-extfile', tmp_path, '-extensions', 'v3_ext',
            ], input=context.require_request)
        context.add(output)
        return context

    def get_info(self, context):
        output = self.run([
            'x509', '-noout',
            '-dates', '-subject', '-issuer', '-email', '-fingerprint',
            '-ext', 'basicConstraints,keyUsage,subjectAltName',
            '-nameopt', 'esc_2253,esc_2254,esc_ctrl,utf8,sep_comma_plus_space',
            ], input=context.require_certificate)
        return CertInfo.parse(output)
