# Changelog

## [0.2.4](https://github.com/poweradmin/certbot-dns-poweradmin/compare/v0.2.3...v0.2.4) (2026-07-09)


### Bug Fixes

* sanitize redirect Location and reason phrase in errors, reject API keys with whitespace/line breaks ([fd78639](https://github.com/poweradmin/certbot-dns-poweradmin/commit/fd7863945f4872a917b76a0ad3843dba98f321ba))

## [0.2.3](https://github.com/poweradmin/certbot-dns-poweradmin/compare/v0.2.2...v0.2.3) (2026-07-06)


### Bug Fixes

* quote TXT content for API v1, add timeouts, harden response parsing and error reporting ([310e97f](https://github.com/poweradmin/certbot-dns-poweradmin/commit/310e97fc26fab6ea4ee3f0fba6553619e61741ff))
* reject query/fragment in API URL, accept uppercase api_version, skip boolean zone IDs ([dad6e36](https://github.com/poweradmin/certbot-dns-poweradmin/commit/dad6e361d486734736f215db21ce06f1645c88f2))
* reject redirects and bad API URLs, skip disabled records, encode record IDs, close session ([6bc1b97](https://github.com/poweradmin/certbot-dns-poweradmin/commit/6bc1b974e5d33cea2ebd91ae0170335e291ac2dd))
* skip unusable record IDs, escape embedded quotes in TXT content, truncate long API error hints ([a047217](https://github.com/poweradmin/certbot-dns-poweradmin/commit/a047217c6ce1c3096123d375c0e54004ddcaad74))
* strip control chars from API error hints, validate pre-quoted TXT content, close client after cleanup, distinct 304 error ([8b00f81](https://github.com/poweradmin/certbot-dns-poweradmin/commit/8b00f81e92521aa4cedb09869da4be54f2f3627c))


### Documentation

* update compatibility table and API URL troubleshooting in README ([d39650f](https://github.com/poweradmin/certbot-dns-poweradmin/commit/d39650fe30b8af4c98c377377db7187c9e2f7e05))

## [0.2.2](https://github.com/poweradmin/certbot-dns-poweradmin/compare/v0.2.1...v0.2.2) (2026-05-30)


### Bug Fixes

* distinguish API HTTP errors from not-found in lookups ([30dbe54](https://github.com/poweradmin/certbot-dns-poweradmin/commit/30dbe54239b8c2cd5777fe35ca379d693421f447))
* distinguish API HTTP errors from not-found in zone/record lookups ([beefe4d](https://github.com/poweradmin/certbot-dns-poweradmin/commit/beefe4def76b0b193d811200a09c7c429f18c4aa))

## [0.2.1](https://github.com/poweradmin/certbot-dns-poweradmin/compare/v0.2.0...v0.2.1) (2026-05-10)


### Security

* bump `requests` to 2.33.1, `urllib3` to 2.7.0, `pyopenssl` to 26.2.0 to address CWE-120 (pyopenssl buffer overflow), CWE-377 (requests insecure temp file), CWE-770 / CWE-409 (urllib3 resource exhaustion / data amplification) ([1148295](https://github.com/poweradmin/certbot-dns-poweradmin/commit/114829569f571c9ecd0645294c6b773312b12e71))
