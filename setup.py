#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name='pe_tools',
    version='0.2.3',

    url='https://github.com/avast/pe_tools',
    maintainer='Martin Vejnár',
    maintainer_email='martin.vejnar@avast.com',

    packages=['pe_tools'],
    install_requires=['grope'],

    entry_points={
        'console_scripts': [
            'peresed = pe_tools.peresed:main',
            ],
        }
    )
