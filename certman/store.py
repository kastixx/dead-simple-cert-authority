__all__ = [ 'Store' ]

from .context import Context

import os
from collections import namedtuple

class Store:
    SELF_SIGNED_SUBDIR = '+SELF_SIGNED'
    PRIVATE_KEY_SUBDIR = 'private'
    PRIVATE_KEY_SUBDIR_PERMS = 0o700
    PRIVATE_KEY_FILE_PERMS = 0o600
    CA_DIR_SUFFIX = '.d'
    CERT_SUFFIX = '.pem'
    KEY_SUFFIX = '.key'
    RSA_KEY_SUFFIX = '.rsa'
    REQUEST_SUFFIX = '.req'

    CertificatePaths = namedtuple('CertificatePaths', 'cert key rsa_key req'.split())

    def __init__(self, root_dir=None, key_dir=None):
        self.root_dir = root_dir or os.path.abspath(os.curdir)
        self.key_dir = key_dir or os.path.join(self.root_dir, self.PRIVATE_KEY_SUBDIR)

    @classmethod
    def self_signed_context(cls):
        return Context(cls.SELF_SIGNED_SUBDIR, is_ca=True)

    def make_store_basepaths(self, basename, cert_dir, key_dir=None):
        if not key_dir:
            key_dir = os.path.join(cert_dir, self.PRIVATE_KEY_SUBDIR)

        os.makedirs(cert_dir, exist_ok=True)
        try:
            os.makedirs(key_dir, mode=self.PRIVATE_KEY_SUBDIR_PERMS)
        except FileExistsError:
            os.chmod(key_dir, self.PRIVATE_KEY_SUBDIR_PERMS)

        return (os.path.join(cert_dir, basename), os.path.join(key_dir, basename))

    def load_context(self, context, load_cert=False, load_key=False,
                     load_rsa_key=False, load_req=False):
        paths = self.get_context_paths(context)

        self.verify_exists(context, paths, check_cert=load_cert, check_key=load_key,
                           check_rsa_key=load_rsa_key, check_req=load_req)

        if load_cert:
            context.add_from_file(paths.cert)
        if load_key:
            context.add_from_file(paths.key)
        if load_rsa_key:
            context.add_from_file(paths.rsa_key)
        if load_req:
            context.add_from_file(paths.req)

        return context

    def verify_exists(self, context, paths=None,
                      check_cert=False, check_key=False,
                      check_rsa_key=False, check_req=False, inverted_check=False):
        if not paths:
            paths = self.get_context_paths(context)

        failed_item = None

        if check_cert and inverted_check is os.path.exists(paths.cert):
            failed_item = "cert"
        elif check_key and inverted_check is os.path.exists(paths.key):
            failed_item = "key"
        elif check_rsa_key and inverted_check is os.path.exists(paths.rsa_key):
            failed_item = "rsa_key"
        elif check_req and inverted_check is os.path.exists(paths.req):
            failed_item = "req"

        if not failed_item:
            return

        if context.is_ca:
            description = "CA certificate {}".format(
                    context.basename)
        elif context.ca_context and context.ca_context.basename != self.SELF_SIGNED_SUBDIR:
            description = "certificate {} signed by CA {}".format(
                    context.basename, context.ca_context.basename)
        else:
            description = "self-signed certificate {}".format(
                    context.basename)

        if failed_item == "cert":
            desc_prefix = ""
        elif failed_item == "key":
            desc_prefix = "Private key for "
        elif failed_item == "rsa_key":
            desc_prefix = "RSA private key for "
        elif failed_item == "req":
            desc_prefix = "CSR for "

        if inverted_check:
            raise FileExistsError('{}{} already exists in the store'.format(
                desc_prefix, description))
        else:
            raise FileNotFoundError('{}{} was not found in the store'.format(
                desc_prefix, description))

    def get_context_paths(self, context):
        if context.is_ca:
            cert_basepath, key_basepath = self.make_store_basepaths(
                    context.basename, self.root_dir, self.key_dir)

        else:
            if context.ca_context:
                ca_basename = context.ca_context.basename
            else:
                ca_basename = self.CA_DIR_SUFFIX

            ca_basepath, _ = self.make_store_basepaths(
                    ca_basename, self.root_dir, self.key_dir)
            cert_basepath, key_basepath = self.make_store_basepaths(
                    context.basename, ca_basepath + self.CA_DIR_SUFFIX)

        return self.CertificatePaths(cert_basepath + self.CERT_SUFFIX,
                                     key_basepath + self.KEY_SUFFIX,
                                     key_basepath + self.RSA_KEY_SUFFIX,
                                     cert_basepath + self.REQUEST_SUFFIX)

    @staticmethod
    def restricted_opener(filename, flags):
        return os.open(filename, flags, mode=Store.PRIVATE_KEY_FILE_PERMS)

    def store(self, context, with_request=False, require_rsa=False):
        paths = self.get_context_paths(context)

        certificate = context.require_certificate
        private_key = context.require_private_key

        if require_rsa:
            rsa_private_key = context.require_rsa_private_key
        else:
            rsa_private_key = context.rsa_private_key

        if with_request:
            request = context.require_request
        else:
            request = None

        with open(paths.cert, 'wt') as fd:
            fd.write(certificate)

        with open(paths.key, 'wt', opener=self.restricted_opener) as fd:
            fd.write(private_key)

        if rsa_private_key:
            with open(paths.rsa_key, 'wt', opener=self.restricted_opener) as fd:
                fd.write(rsa_private_key)

        if request:
            with open(paths.req, 'wt') as fd:
                fd.write(request)
