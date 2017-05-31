#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name='pe-tools',
    version='0.1',

    packages=['pe_tools'],
    install_requires=['six'],

    entry_points={
        'console_scripts': [
            'chverinfo = pe_tools.chverinfo:main',
            ],
        }
    )
