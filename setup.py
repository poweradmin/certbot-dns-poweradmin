from setuptools import setup, find_packages

setup(
    name='certbot-dns-poweradmin',
    version='0.1.0',
    description='PowerAdmin DNS Authenticator plugin for Certbot',
    author='Edmondas Girkantas',
    author_email='edmondas@girkantas.lt',
    url='https://github.com/poweradmin/certbot-dns-poweradmin',
    license='Apache License 2.0',
    python_requires='>=3.10',
    packages=find_packages(),
    install_requires=[
        'certbot>=2.0.0',
        'requests',
    ],
    entry_points={
        'certbot.plugins': [
            'dns-poweradmin = certbot_dns_poweradmin.dns_poweradmin:Authenticator',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Networking',
    ],
)
