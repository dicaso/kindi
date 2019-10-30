# Kindi: kind incommunicados

A small package to deal with secrets in pipelines, such as API keys
for data repositories.  Named in reference to
[Al-Kindi](https://en.wikipedia.org/wiki/Al-Kindi), one of the fathers
of cryptography.

## Install

This package is intended more as a library for other python packages,
that will then have it as a dependency. If you want to use it
directly:

    pip3 install kindi

## Configuration

The default configuration will encrypt your secrets and store it in a
database. If you trust your system - because you are the only one with
admin rights - you can save the following configuration file `~/.incommunicados.cfg`:

    [kindi]
    security_level=LOW
    storage=FILE

With this configuration the secrets will not be encrypted, but they
will only be readable by your user. They will also be stored in a flat
text file for easy editing. It is a strong recommendation to only use
this configuration on a system you trust sufficiently.

## Developers

Developers should make calls for secrets in the following way,
replacing `my_package` with the name of their package:

    from kindi import Secrets
    my_package_secrets = Secrets(default_section='my_package')
    my_package_secrets['email']
    my_package_secrets['email','different_section'] # key storred in different section

