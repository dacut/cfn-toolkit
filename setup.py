#!/usr/bin/env python3
from setuptools import setup

with open("requirements.txt", "r") as fd:
    packages = fd.read().split("\n")

with open("requirements-test.txt", "r") as fd:
    test_packages = fd.read().split("\n")

setup(
    name="CFNGenerator",
    version="0.1.0",
    packages=["cfntoolkit"],
    py_modules=["handler"],
    setup_requires=["nose>=1.0"],
    install_requires=packages,
    tests_require=["coverage>=4.0", "moto", "nose>=1.0"],
    test_suite="tests",

    # PyPI information
    author="David Cuthbert",
    author_email="dacut@kanga.org",
    description="Custom CloudFormation resources",
    license="Apache",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords=['aws', 'cloudformation'],
    url="https://github.com/dacut/cfn-toolkit",
    zip_safe=False,
)
