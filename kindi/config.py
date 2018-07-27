# -*- coding: utf-8 -*-
"""Kindi configuration

Settings for how kindi database is stored.

Options:
    security_level: LOW, MEDIUM, or HIGH
    storage: FILE, DATABASE
"""

import configparser, os
configFiles = [
    os.path.expanduser('~/.incommunicados.cfg'),
    '/usr/local/etc/kindi.cfg'
]

# Default configuration
config = configparser.ConfigParser()
config['kindi'] = {
    'security_level': os.environ.get('KINDI_SECURITY_LEVEL','LOW'), # options: LOW, MEDIUM, HIGH
    'storage': os.environ.get('KINDI_STORAGE','DATABASE') # options: FILE, DATABASE
}

# Read configuration files
config.read(configFiles)
