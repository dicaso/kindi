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

class Secrets(object):
    class __SecretsSingleton:
        def __init__(self,parent):
            self.__parent = parent
            self.secrets = configparser.ConfigParser()
            self.secretConfigFile = os.path.expanduser('~/.incommunicados')
            if os.path.exists(self.secretConfigFile):
                self.secrets.read(self.secretConfigFile)

        def __str__(self):
            return repr(self) + repr(self.secrets)

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
                with open(self.secretConfigFile,'wt') as configFile:
                    self.secrets.write(configFile)
                # chmod to make read/write only for user
                os.chmod(self.secretConfigFile, 0o600)
            return s

    instance = None

    def __init__(self, *args, default_section = 'API', **kwargs):
        self.default_section = default_section
        if not Secrets.instance:
            Secrets.instance = Secrets.__SecretsSingleton(*args, parent=self, **kwargs)

    def __getattr__(self, name):
        return getattr(self.instance, name)


