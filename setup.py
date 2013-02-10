#!/usr/bin/python

from distutils.core import setup

setup(name='logwrap',
      version='1.0',
      description='Log File Encapsulator',
      author='Pete Kazmier',
      author_email='pete-logwrap@kazmier.com',
      url='http://www.kazmier.com/computer/logwrap/',
      scripts=['bin/logwrap', 'bin/re-profile'],
      package_dir={'': 'lib'},
      packages=['com',
                'com.kazmier',
                'com.kazmier.event',
                'com.kazmier.utils',
                'com.kazmier.logwrap'],
      )
