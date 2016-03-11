"""
DNS Zone File
==============

"""

from setuptools import setup, find_packages

setup(
    name='zonefile',
    version='0.0.0',
    url='https://github.com/blockstack/dns-zone-file-py',
    license='MIT',
    author='Blockstack Developers',
    author_email='hello@onename.com',
    description=("Library for creating and parsing DNS Zone Files"),
    keywords='dns zone file zonefile parse create',
    packages=find_packages(),
    zip_safe=False,
    install_requires=[
        'Jinja2==2.8'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
