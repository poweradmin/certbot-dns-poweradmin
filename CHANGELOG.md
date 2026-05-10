# Changelog

## [0.2.1](https://github.com/poweradmin/certbot-dns-poweradmin/compare/v0.2.0...v0.2.1) (2026-05-10)


### Security

* bump `requests` to 2.33.1, `urllib3` to 2.7.0, `pyopenssl` to 26.2.0 to address CWE-120 (pyopenssl buffer overflow), CWE-377 (requests insecure temp file), CWE-770 / CWE-409 (urllib3 resource exhaustion / data amplification) ([1148295](https://github.com/poweradmin/certbot-dns-poweradmin/commit/114829569f571c9ecd0645294c6b773312b12e71))
