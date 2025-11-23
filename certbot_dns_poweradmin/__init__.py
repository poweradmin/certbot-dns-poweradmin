"""
The `~certbot_dns_poweradmin._internal.dns_poweradmin` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the PowerAdmin API.


Named Arguments
---------------

==========================================  ===================================
``--dns-poweradmin-credentials``            PowerAdmin credentials INI file.
                                            (Required)
``--dns-poweradmin-propagation-seconds``    The number of seconds to wait for
                                            DNS to propagate before asking the
                                            ACME server to verify the DNS
                                            record.
                                            (Default: 120)
==========================================  ===================================


Credentials
-----------

Use of this plugin requires a configuration file containing PowerAdmin API
credentials, obtained from your PowerAdmin installation.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # PowerAdmin API credentials
   dns_poweradmin_api_url = https://poweradmin.example.com
   dns_poweradmin_api_key = your-api-key-here
   dns_poweradmin_api_version = v2

The path to this file can be provided interactively or using the
``--dns-poweradmin-credentials`` command-line argument. Certbot records the path
to this file for use during renewal but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   PowerAdmin account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if this server isn't managing those domains.

Certbot will emit a warning if it detects that the credential file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credential configuration file", followed by the path to the credential
file. This warning will be emitted each time Certbot uses the credential file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


API Version
-----------

PowerAdmin supports two API versions:

- ``v1``: Stable API version
- ``v2``: Enhanced API with additional features (default)

You can specify the API version in your credential file using the
``dns_poweradmin_api_version`` option. If not specified, ``v2`` is used by default.


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --authenticator dns-poweradmin \\
     --dns-poweradmin-credentials ~/.secrets/certbot/poweradmin.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --authenticator dns-poweradmin \\
     --dns-poweradmin-credentials ~/.secrets/certbot/poweradmin.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 300 seconds
             for DNS propagation

   certbot certonly \\
     --authenticator dns-poweradmin \\
     --dns-poweradmin-credentials ~/.secrets/certbot/poweradmin.ini \\
     --dns-poweradmin-propagation-seconds 300 \\
     -d example.com

"""
from certbot_dns_poweradmin._internal.dns_poweradmin import Authenticator

__all__ = ["Authenticator"]
