#!/usr/bin/env python3


from setuptools import setup, find_packages
import os

with open(os.path.join('src', '__init__.py'), 'r') as f:
    for line in f:
        if line.startswith('__version__'):
            version = line.split('=')[1].strip().strip("'\"")
            break

try:
    with open('README.md', 'r') as f:
        long_description = f.read()
except:
    long_description = "Utility for preparing FreeIPA for Group Policy Management"

setup(
    name="ipa-gpo-install",
    version=version,
    author="Danila Skachedubov",
    author_email="skachedubov@altlinux.org",
    description="Utility for preparing FreeIPA for Group Policy Management",
    long_description=long_description,

    packages=find_packages(),
    package_dir={"": "."},

    data_files=[
        ('share/ipa-gpo-install/data', ['']),
        ('bin', ['bin/ipa-gpo-install']),
        ('share/locale/ru/LC_MESSAGES', ['locale/ru/LC_MESSAGES/ipa-gpo-install.mo']),
    ],

    install_requires=[

    ],

    scripts=[
        "bin/ipa-gpo-install",
    ],

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPLv3",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.6",
)