#!/usr/bin/env python3

# Note!
# ' are required, do not use any '.

# setup.
from setuptools import setup, find_packages
setup(
	name='ssht00ls',
	version='3.21.1',
	description='Some description.',
	url='http://github.com/vandenberghinc/ssht00ls',
	author='Daan van den Bergh',
	author_email='vandenberghinc.contact@gmail.com',
	license='MIT',
	packages=find_packages(),
	zip_safe=False,
      include_package_data=True,
	install_requires=[
            #'encrypti0n>=3.20.4',
            #'dev0s>=2.16.4',
            #'netw0rk>=1.9.3',
            #'syst3m>=2.16.7',
        ],)