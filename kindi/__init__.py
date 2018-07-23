# -*- coding: utf-8 -*-
"""Kind incommunicados main module

Contains the singleton Secrets class, that can be instantiated
in different packages.

Ideally, each package should write to its own section, to not
overwrite configs from other packages. A default section 'API'
is provided, but developers are recommended not to use it.

TODO:
    - add option to encrypt, although this would prevent use in non-interactive cases
"""
import configparser, os
from cryptography.fernet import Fernet
from io import StringIO
from kindi.config import config

class Secrets(object):
    class __SecretsSingleton:
        def __init__(self, parent, ekey=None):
            self.__parent = parent
            self.security = config['kindi']['security_level']
            self.storage = config['kindi']['storage']
            if self.security != 'LOW':
                if ekey:
                    self.ekey = ekey
                else:
                    raise Exception('Cannot instantiate Secrets for MEDIUM and HIGH security if no key is provided')
            if self.storage == 'DATABASE': self.__conn = None
            self.secrets = configparser.ConfigParser()
            self.secretConfigFile = os.path.expanduser('~/.incommunicados')
            if os.path.exists(self.secretConfigFile):
                self.read_secretsfile()

        def __str__(self):
            return repr(self) + repr(self.secrets)

        def __get_cursor(self):
            if not self.__conn:
                import sqlite3
                self.__conn = sqlite3.connect(self.secretConfigFile)
            return self.__conn.cursor()
        
        def __create_tables(self):
            cursor = self.__get_cursor()
            cursor.execute(
                '''CREATE TABLE IF NOT EXISTS configblobs (
 blob_id integer PRIMARY KEY,
 name text NOT NULL UNIQUE,
 content blob NOT NULL UNIQUE
);
'''
            )
            cursor.execute(
                '''CREATE TABLE IF NOT EXISTS admin (
 key text NOT NULL UNIQUE,
 value text NOT NULL UNIQUE
);
'''
            )
            cursor.close()
            
        def getsecret(self,key,section='',fail=False,timeout=120):
            """Get secret

            If empty string, ask user to set it and save to user config file.
            
            Args:
                key (str): Secret key name.
                section (str): Section name. Defaults to default_section of singleton wrapper class.
                  This allows different packages using the same singleton with different default_section.
                fail (bool): If fail, fails immediately if key not provided in config.
                timeout (int): If key not in config, wait timeout seconds for user to provide.
                  Fail if not provided within timeframe.
            """
            if not section: section = self.__parent.default_section
            s = self.secrets.get(section, key, fallback = '')
            if not s:
                if fail: raise KeyError('{} {} not in config'.format(section,key))
                if timeout:
                    import signal
                    def interrupted(signum, frame):
                        print('Key was not provided within',timeout,'seconds.')
                        raise KeyError('{} {} not in config'.format(section,key))
                    signal.signal(signal.SIGALRM, interrupted)
                    signal.alarm(timeout)
                s = input('Provide key for {}/{}: '.format(section,key))
                try:
                    self.secrets[section][key] = s
                except KeyError:
                    # Section does not yet exist in config, so create
                    self.secrets[section] = {key: s}
                if timeout: signal.alarm(0) # disable alarm
                self.write_secretsfile()
            return s

        def read_secrets(self):
            if self.storage == 'FILE':
                self.__read_secrets_file()
            else: self.__read_secrets_db()
        
        def __read_secrets_file(self):
            if self.security == 'LOW':
                self.secrets.read(self.secretConfigFile)
            elif self.security == 'MEDIUM':
                with open(self.secretConfigFile,'rb') as configFile:
                    token = configFile.read()
                f = Fernet(self.ekey)
                self.secrets.read_string(
                    f.decrypt(token).decode()
                )
            elif self.security == 'HIGH':
                # if non interactive job, delete file after reading
                pass
            else:
                raise Exception(f'''Unknown security level {self.security}.
Env variable KINDI_SECURITY_LEVEL should be set to LOW, MEDIUM or HIGH'''
                )

        def __read_secrets_db(self):
            pass

        def write_secrets(self):
            if self.storage == 'FILE':
                self.__write_secrets_file()
            else: self.__write_secrets_db()

        def write_secrets_file(self):
            if self.security == 'LOW':
                with open(self.secretConfigFile,'wt') as configFile:
                    self.secrets.write(configFile)
            elif self.security == 'MEDIUM':
                f = Fernet(self.ekey)
                tokenText = StringIO()
                self.secrets.write(tokenText)
                token = f.encrypt(tokenText.getvalue().encode())
                cursor.execute('INSERT INTO t VALUES(?)', [buffer(ablob)])
                with open(self.secretConfigFile,'wb') as configFile:
                    configFile.write(token)
            elif self.security == 'HIGH':
                raise NotImplementedError("when implemented will create encrypted versions for one time use in non-interactive CLI")
            # chmod to make read/write only for user
            os.chmod(self.secretConfigFile, 0o600)

    instance = None

    def __init__(self, *args, default_section = 'API', **kwargs):
        self.default_section = default_section
        if not Secrets.instance:
            Secrets.instance = Secrets.__SecretsSingleton(*args, parent=self, **kwargs)

    def __getattr__(self, name):
        return getattr(self.instance, name)


# Utilities
def make_new_ekey():
    return Fernet.generate_key()
