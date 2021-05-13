# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='TripWire',
    version='0.1',
    description='A Mac OSX suitable portscan honeypot built around Scapy.',
    long_description=readme,
    author='Vincent van Trigt',
    author_email='vincentvantrigt@protonmail.com',
    url='https://github.com/CheekyClaps/Tripwire-Portscan-Honeypot',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)
