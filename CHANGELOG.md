# Changelog

## [0.2.2](https://github.com/poweradmin/certbot-dns-poweradmin/compare/v0.2.1...v0.2.2) (2026-05-30)


### Bug Fixes

* distinguish API HTTP errors from not-found in lookups ([30dbe54](https://github.com/poweradmin/certbot-dns-poweradmin/commit/30dbe54239b8c2cd5777fe35ca379d693421f447))
* distinguish API HTTP errors from not-found in zone/record lookups ([beefe4d](https://github.com/poweradmin/certbot-dns-poweradmin/commit/beefe4def76b0b193d811200a09c7c429f18c4aa))

## [0.2.1](https://github.com/poweradmin/certbot-dns-poweradmin/compare/v0.2.0...v0.2.1) (2026-05-10)


### Security

* bump `requests` to 2.33.1, `urllib3` to 2.7.0, `pyopenssl` to 26.2.0 to address CWE-120 (pyopenssl buffer overflow), CWE-377 (requests insecure temp file), CWE-770 / CWE-409 (urllib3 resource exhaustion / data amplification) ([1148295](https://github.com/poweradmin/certbot-dns-poweradmin/commit/114829569f571c9ecd0645294c6b773312b12e71))
