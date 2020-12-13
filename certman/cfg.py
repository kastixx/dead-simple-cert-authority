__all__ = [ 'Config' ]

from collections import OrderedDict

class Config:
    def __init__(self):
        self.sections = OrderedDict()
        self.sections[''] = OrderedDict()

    @property
    def default(self):
        return self.sections['']

    def __setitem__(self, key, value):
        self.sections[key] = value

    def __getitem__(self, key):
        try:
            return self.sections[key]
        except KeyError:
            newsection = OrderedDict()
            self.sections[key] = newsection
            return newsection

    @property
    def generate(self):
        lines = []
        for name, content in self.sections.items():
            if name:
                lines.append('[ {} ]\n'.format(name))

            for key, value in content.items():
                lines.append('{} = {}\n'.format(key, value))

            lines.append('\n')

        return ''.join(lines)
