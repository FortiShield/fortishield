#!/usr/bin/env python

# Copyright (C) 2015, KhulnaSoft Ltd.
# Created by KhulnaSoft, Ltd. <info@khulnasoft.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from fortishield import __version__

from setuptools import setup, find_namespace_packages

setup(name='fortishield',
      version=__version__,
      description='Fortishield control with Python',
      url='https://github.com/fortishield',
      author='Fortishield',
      author_email='hello@khulnasoft.com',
      license='GPLv2',
      packages=find_namespace_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
      package_data={'fortishield': ['core/fortishield.json',
                              'core/cluster/cluster.json', 'rbac/default/*.yaml']},
      include_package_data=True,
      install_requires=[],
      zip_safe=False,
      )
