__all__ = [ 'make_temp_file', 'clean_temp_files' ]

import tempfile
import os

class TempFileManager:
    _instance = None

    @classmethod
    def instance(cls):
        if not cls._instance:
            cls._instance = cls()

        return cls._instance

    def _try_temp_dir(self, parent_dir):
        if not os.access(parent_dir, os.X_OK | os.R_OK | os.W_OK):
            return

        tmp_dir = parent_dir + '/ca_cert_manager'
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir, mode=0o700)

        if os.access(tmp_dir, os.X_OK | os.R_OK | os.W_OK):
            return tmp_dir

        return

    def _get_temp_dir(self):
        tmp_dir = self._try_temp_dir('/run/user/{}'.format(os.getuid()))
        if tmp_dir:
            return tmp_dir

        tmp_dir = self._try_temp_dir('/tmp')
        if tmp_dir:
            return tmp_dir

        raise Exception("No suitable temporary directory found")

    def __init__(self):
        self.files = []
        self.tempdir = self._get_temp_dir()

    def create(self, content):
        fd, name = tempfile.mkstemp(prefix='cacertmanager', dir=self.tempdir)
        self.files.append(name)
        os.write(fd, content.encode())
        os.close(fd)
        return name

    def clean(self):
        for filename in self.files:
            try:
                os.unlink(filename)
            except FileNotFoundError:
                pass

        self.files = []

def make_temp_file(content):
    return TempFileManager.instance().create(content)

def clean_temp_files():
    TempFileManager.instance().clean()
