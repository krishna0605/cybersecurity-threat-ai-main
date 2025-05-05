from setuptools import setup, find_packages

setup(
    name="cybersecurity-threat-ai",
    version="0.1.0",
    packages=find_packages(),
    setup_requires=[
        "setuptools>=69.0.2",
        "setuptools-distutils>=36.0.0"
    ],
    install_requires=[
        "flask==2.2.3",
        "werkzeug==2.2.3",
        "gunicorn==20.1.0"
    ]
) 