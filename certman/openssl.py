__all__ = [ 'OpenSSL' ]

import subprocess
import re

from .context import Context

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
        output = self.run('rsa', input=context.require_private_key)
        context.add(output)
        return context

    def request(self, context, request):
        cfg_text = request.config.generate
        output = self.run('req -new -config -'.split(), input=cfg_text)
        context.add(output)
        return context

    def self_signed(self, context, request):
        cfg_text = request.config.generate
        output = self.run('req -x509 -config - -days {}'.format(request.days).split(), input=cfg_text)
        context.add(output)
        return context

    def signed(self, context, request, ca_context):
        self.request(context, request)
        output = self.run([
            'x509', '-req', '-in', '-',
            '-CA', ca_context.certificate_path,
            '-CAkey', ca_context.private_key_path,
            '-days', str(request.days),
            ], input=context.require_request)
        context.add(output)
        return context
