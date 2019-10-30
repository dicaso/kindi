# -*- coding: utf-8 -*-
"""Kindi configuration

Settings for how kindi database is stored.

Options:
    security_level: LOW, MEDIUM, or HIGH
    storage: FILE, DATABASE
"""

import configparser, os, appdirs
configdir = appdirs.AppDirs('kindi').user_config_dir
configFiles = [
    os.path.expanduser('~/.incommunicados.cfg'),
    os.path.join(configdir, 'kindi.cfg')
]

# Check existance of configdir
if not os.path.exists(configdir):
    os.makedirs(configdir, mode=0o700)
    print('created kindi configdir', configdir)

# Default configuration
config = configparser.ConfigParser()
config['kindi'] = {
    'security_level': os.environ.get('KINDI_SECURITY_LEVEL','LOW'), # options: LOW, MEDIUM, HIGH
    'storage': os.environ.get('KINDI_STORAGE','DATABASE') # options: FILE, DATABASE
}

# Read configuration files
config.read(configFiles)
