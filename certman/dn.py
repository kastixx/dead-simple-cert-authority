__all__ = [ 'DNSection' ]

from collections import OrderedDict

DN_FIELD_PAIRS = (
        ('C', 'country'),
        ('ST', 'state'),
        ('L', 'locality'),
        ('O', 'organization'),
        ('OU', 'organization_unit'),
        ('CN', 'common_name'),
        ('emailAddress', 'email_address'),
        )

class DNSection:
    def __init__(self, country=None, state=None, locality=None,
                 organization=None, organization_units=[],
                 common_name=None, email_address=None):
        self.country = country
        self.state = state
        self.locality = locality
        self.organization = organization
        self.organization_units = organization_units[:] if organization_units else []
        self.common_name = common_name
        self.email_address = email_address

    @classmethod
    def from_string(cls, string):
        if not string:
            return None

        string = string.strip()
        if not string:
            return None

        country = None
        state = None
        locality = None
        organization = None
        organization_units = []
        common_name = None
        email_address = None

        for pair in string.split(', '):
            key, value = pair.split('=', 1)
            value = value.strip()

            if key == 'C':
                country = value
            elif key == 'CN':
                common_name = value
            elif key == 'emailAddress':
                email_address = value
            elif key == 'L':
                locality = value
            elif key == 'O':
                organization = value
            elif key == 'OU':
                organization_units.append(value)
            elif key == 'S':
                state = value
            else:
                raise KeyError("Unexpected DN field: {}".format(key))

        return cls(country=country,
                   common_name=common_name,
                   email_address=email_address,
                   locality=locality,
                   organization=organization,
                   organization_units=organization_units,
                   state=state)

    def items(self):
        if self.country is not None:
            yield ('C', self.country)
        if self.state is not None:
            yield ('ST', self.state)
        if self.locality is not None:
            yield ('L', self.locality)
        if self.organization is not None:
            yield ('O', self.organization)
        if len(self.organization_units) > 1:
            for ou_num, ou in enumerate(self.organization_units):
                yield ('{}.OU'.format(ou_num), ou)
        elif len(self.organization_units) == 1:
            yield ('OU', self.organization_units[0])
        if self.common_name is not None:
            yield ('CN', self.common_name)
        if self.email_address is not None:
            yield ('emailAddress', self.email_address)

    @property
    def ordered_dict(self):
        return OrderedDict(self.items())

