from setuptools import setup, find_packages

setup(
    name="cybersecurity-threat-ai",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "flask==2.2.3",
        "werkzeug==2.2.3",
        "gunicorn==20.1.0"
    ]
) 