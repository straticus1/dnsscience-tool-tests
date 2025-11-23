#!/usr/bin/env python3
"""
DNSScience CLI Setup Script
"""

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='dnsscience-cli',
    version='1.0.0',
    description='DNSScience.io Command Line Interface - Advanced DNS Intelligence',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='DNSScience.io',
    author_email='support@dnsscience.io',
    url='https://dnsscience.io',
    py_modules=['dnsscience'],
    install_requires=[
        'click>=8.0.0',
        'requests>=2.25.0',
        'tabulate>=0.8.9',
        'PyYAML>=5.4.0',
    ],
    entry_points={
        'console_scripts': [
            'dnsscience=dnsscience:cli',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: System :: Networking',
        'Topic :: Utilities',
    ],
    python_requires='>=3.7',
    keywords='dns dnssec security cli email ssl rdap traceroute',
)
