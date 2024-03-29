__all__ = [
        'Request',
        'BITS_2K', 'BITS_4K',
        'HASH_SHA256', 'HASH_SHA512',
        ]

from collections import OrderedDict

from .dn import DNSection
from .cfg import Config

BITS_2K = 2048
BITS_4K = 4096

HASH_SHA256 = 'sha256'
HASH_SHA512 = 'sha512'

class Request:
    # defaults
    bits = BITS_4K
    days = 3650
    hash_algo = HASH_SHA512

    def __init__(self, dn=None, is_ca=False, domain_names=None,
                 bits=None, days=None, hash_algo=None):
        self.dn = dn or DNSection()
        self.is_ca = is_ca
        self.domain_names = domain_names

        if bits:
            self.bits = bits

        if days:
            self.days = days

        if hash_algo:
            self.hash_algo = hash_algo

    @property
    def config(self):
        config = Config()

        req = config['req']
        req['default_bits'] = self.bits
        req['default_md'] = self.hash_algo
        req['distinguished_name'] = 'req_dn'
        req['encrypt_key'] = 'no'
        req['prompt'] = 'no'
        req['req_extensions'] = 'v3_ext'
        req['x509_extensions'] = 'v3_ext'

        config['req_dn'] = self.dn.ordered_dict

        v3_ext = config['v3_ext']
        if self.is_ca:
            v3_ext['basicConstraints'] = 'CA:TRUE'
            v3_ext['keyUsage'] = 'keyCertSign, cRLSign'
        else:
            v3_ext['basicConstraints'] = 'CA:FALSE'
            v3_ext['extendedKeyUsage'] = 'serverAuth, clientAuth'

        if self.domain_names:
            v3_ext['subjectAltName'] = '@req_subject'
            req_subject = config['req_subject']

            for num, name in enumerate(self.domain_names):
                req_subject['DNS.{}'.format(num + 1)] = name

        return config
