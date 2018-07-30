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
            # Settings
            self.__parent = parent
            self.security = config['kindi']['security_level']
            self.storage = config['kindi']['storage']
            self.__ekey = ekey
            if self.storage == 'DATABASE': self.__conn = None
            self.secretConfigFile = os.path.expanduser(
                '~/.incommunicados' if self.storage == 'FILE' else '~/.incommunicadob'
            )
            if self.security == 'LOW' or ekey:
                self.init_secrets()
            else:
                self.secrets = None

        def init_secrets(self):
            self.secrets = configparser.ConfigParser()
            if os.path.exists(self.secretConfigFile):
                self.read_secrets()

        @property
        def ekey(self):
            """Encryption key

            If not set at initiation, and non-LOW security,
            asks input from user. In MEDIUM security, ekey
            is stored in Secrets object. Higher security settings
            will ask for the key for each read and write access.
            """
            if self.security == 'LOW':
                raise Exception('LOW security does not need access to encryption key.')
            if self.__ekey:
                ekey = self.__ekey
            else:
                ekey = self.getuserinput(
                    'Provide kindi secrets encryption key: ',
                    'Cannot instantiate Secrets for MEDIUM and HIGH security if no key is provided'
                )
                if self.security == 'MEDIUM':
                    self.__ekey = ekey
            return ekey
            
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
 blob_id INTEGER PRIMARY KEY,
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

        @staticmethod
        def getuserinput(inputmsg,timeoutmsg='Input not given on time in a non-interactive job.',timeout=120):
            if timeout and not hasattr(os.sys,'ps1'):
                import signal
                def interrupted(signum, frame):
                    raise KeyError(timeoutmsg)
                signal.signal(signal.SIGALRM, interrupted)
                signal.alarm(timeout)
            else: timeout = False # timeout disabled in interactive mode
            inp = input(inputmsg)
            if timeout: signal.alarm(0) # disable alarm
            return inp
            
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
            if not self.secrets: self.init_secrets()
            if not section: section = self.__parent.default_section
            s = self.secrets.get(section, key, fallback = '')
            if not s:
                if fail: raise KeyError(f'{section} {key} not in config')
                s = self.getuserinput(
                    f'Provide key for {section}/{key}: ',
                    f'''Key was not provided within {timeout} seconds.
{section} {key} not in config''',
                    timeout
                )
                try:
                    self.secrets[section][key] = s
                except KeyError:
                    # Section does not yet exist in config, so create
                    self.secrets[section] = {key: s}
                self.write_secrets()
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
            cursor = self.__get_cursor()
            configdb = cursor.execute('SELECT content FROM configblobs WHERE name = ?',(self.security,)).fetchone()
            if configdb:
                configstr = configdb[0]
                if self.security != 'LOW':
                    f = Fernet(self.ekey)
                    configstr = f.decrypt(configstr).decode()
                self.secrets.read_string(configstr)
            cursor.close()

        def write_secrets(self):
            configText = StringIO()
            self.secrets.write(configText)
            if self.storage == 'FILE':
                self.__write_secrets_file(configText.getvalue())
            else: self.__write_secrets_db(configText.getvalue())
            # chmod to make read/write only for user
            os.chmod(self.secretConfigFile, 0o600)

        def __write_secrets_file(self,configstr):
            if self.security == 'LOW':
                with open(self.secretConfigFile,'wt') as configFile:
                    configFile.write(configstr)
            elif self.security == 'MEDIUM':
                f = Fernet(self.ekey)
                token = f.encrypt(configstr.encode())
                with open(self.secretConfigFile,'wb') as configFile:
                    configFile.write(token)
            elif self.security == 'HIGH':
                raise NotImplementedError("when implemented will create encrypted versions for one time use in non-interactive CLI")

        def __write_secrets_db(self,configstr):
            import sqlite3
            self.__create_tables()
            if self.security != 'LOW':
                f = Fernet(self.ekey)
                configstr = f.encrypt(configstr.encode())
            cursor = self.__get_cursor()
            try:
                cursor.execute('INSERT INTO configblobs VALUES(?,?,?)', (None,self.security,configstr))
            except sqlite3.IntegrityError:
                cursor.execute('UPDATE configblobs SET content = ? WHERE name = ?', (configstr,self.security))
            cursor.close()
            self.__conn.commit()
            
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
