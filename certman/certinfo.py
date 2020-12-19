__all__ = [ 'CertInfo' ]

import re
from .dn import DNSection

# notBefore=Dec 19 13:23:21 2020 GMT
# notAfter=Dec 17 13:23:21 2030 GMT
# subject=CN= wildcard.foo.name
# issuer=CN= dlmtest1-web-ca
# SHA1 Fingerprint=1D:84:43:24:13:2C:25:C6:EF:BD:AC:95:F4:FF:B1:9E:A9:DD:1D:7D
# X509v3 Basic Constraints: 
#     CA:FALSE
# X509v3 Subject Alternative Name: 
#     DNS:foo.name, DNS:*.foo.name

class CertInfo:
    issuer = ""
    subject = ""
    fingerprint = ""
    not_before_raw = None
    not_after_raw = None
    _basic_constraints = None
    _extended_usage = None
    _subject_alt_name = None
    _key_usage = None

    RE_PARAM_LINE = re.compile(r'^([^\s=][^=]+)=(.*)$')
    RE_EXTENSION_LINE = re.compile(r'^X509v3 (.+?):\s*$')

    EXTENSION_NAMES = set((
        'Basic Constraints',
        'Subject Alternative Name',
    ))

    @property
    def subject_dn(self):
        return DNSection.from_string(self.subject)

    @property
    def issuer_dn(self):
        return DNSection.from_string(self.issuer)

    @property
    def extended_usage(self):
        if self._extended_usage is None:
            self._extended_usage = []

        return self._extended_usage

    @property
    def subject_alt_name(self):
        if self._subject_alt_name is None:
            self._subject_alt_name = []

        return self._subject_alt_name

    @property
    def basic_constraints(self):
        if self._basic_constraints is None:
            self._basic_constraints = []

        return self._basic_constraints

    @property
    def key_usage(self):
        if self._key_usage is None:
            self._key_usage = []

        return self._key_usage

    @property
    def is_self_signed(self):
        return self.issuer == self.subject

    @staticmethod
    def iterate_values(lines):
        for line in lines:
            for value in line.split(','):
                value = value.strip()
                if value:
                    yield value

    def add_extension(self, key, *lines):
        value = list(self.iterate_values(lines))
        if key == 'Basic Constraints':
            self._basic_constraints = value
        elif key == 'Subject Alternative Name':
            self._subject_alt_name = value
        elif key == 'Key Usage':
            self._key_usage = value
        else:
            raise KeyError("Unexpected extension: {}".format(key))

    @classmethod
    def parse(cls, text: str):
        certinfo = cls()

        current_extension = None

        for line in text.splitlines():
            m = cls.RE_PARAM_LINE.match(line)
            if m:
                if current_extension:
                    certinfo.add_extension(*current_extension)
                    current_extension = None

                key, value = m.groups()
                if key == 'notBefore':
                    certinfo.not_before_raw = value
                elif key == 'notAfter':
                    certinfo.not_after_raw = value
                elif key == 'issuer':
                    certinfo.issuer = value
                elif key == 'subject':
                    certinfo.subject = value
                elif key == 'SHA1 Fingerprint':
                    certinfo.fingerprint = value
                else:
                    raise KeyError("Unknown parameter: {}".format(key))

                continue

            m = cls.RE_EXTENSION_LINE.match(line)
            if m:
                if current_extension:
                    certinfo.add_extension(*current_extension)

                current_extension = [ m.group(1) ]
                continue

            if line.startswith(' '):
                if current_extension:
                    current_extension.append(line.strip())
                else:
                    raise ValueError("Unexpected indented line: {}".format(line.strip()))

        if current_extension:
            certinfo.add_extension(*current_extension)

        return certinfo
