#!/usr/bin/env python3

# Note!
# ' are required, do not use any '.

# setup.
from setuptools import setup, find_packages
setup(
	name='ssht00ls',
	version='3.21.8',
	description='Some description.',
	url='http://github.com/vandenberghinc/ssht00ls',
	author='Daan van den Bergh',
	author_email='vandenberghinc.contact@gmail.com',
	license='MIT',
	packages=find_packages(),
	zip_safe=False,
      include_package_data=True,
	install_requires=[
            'encrypti0n',
            'dev0s',
            'netw0rk',
            'syst3m',
        ],)