#!/usr/bin/env python3

# Note!
# ' are required, do not use any '.

# setup.
from setuptools import setup, find_packages
setup(
	name='ssht00ls',
	version='3.19.6',
	description='Some description.',
	url='http://github.com/vandenberghinc/ssht00ls',
	author='Daan van den Bergh',
	author_email='vandenberghinc.contact@gmail.com',
	license='MIT',
	packages=find_packages(),
	zip_safe=False,
	install_requires=[
            'asgiref>=3.3.1',
            'certifi>=2020.12.5',
            'chardet>=4.0.0',
            'cl1>=1.12.2',
            'click>=7.1.2',
            'Django>=3.1.6',
            'Flask>=1.1.2',
            'idna>=2.10',
            'itsdangerous>=1.1.0',
            'Jinja2>=2.11.3',
            'MarkupSafe>=1.1.1',
            'pexpect>=4.8.0',
            'ptyprocess>=0.7.0',
            'pycryptodome>=3.10.1',
            'pytz>=2021.1',
            'requests>=2.25.1',
            'selenium>=3.141.0',
            'sqlparse>=0.4.1',
            'urllib3>=1.26.3',
            'Werkzeug>=1.0.1',
            'encrypti0n>=3.19.3',
            'fil3s>=2.13.3',
            'netw0rk>=1.7.9',
            'r3sponse>=2.9.0',
            'syst3m>=2.14.8',
        ],)