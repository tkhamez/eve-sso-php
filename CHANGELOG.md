# Changelog

## 4.0.0

- Removed support for EVE SSO v1, see also
  [SSO Endpoint Deprecations](https://developers.eveonline.com/blog/article/sso-endpoint-deprecations-2).

## 3.0.0

Oct 17, 2021

- Changed constructor parameters of AuthenticationProvider class, see above.
- Added AuthenticationProvider::setProvider() method
- Added AuthenticationProvider::refreshAccessToken() method
- Added AuthenticationProvider::revokeRefreshToken() method
- The JSON Web Key Set is now cached.

## 2.0.2

Jul 17, 2021

- Update PHP requirement to include version 8 (^7.3|^8.0).

## 2.0.1

Nov 17, 2020

- Fix: Require PHP gmp extension (key verification fails without it).

## 2.0.0

Oct 17, 2020

- Raised minimum PHP version to 7.3.
- Updated Guzzle HTTP client to ^7.2 (from ^6.3).

## 1.0.0

Jun 22, 2020

- Forked and renamed from [bravecollective/sso-basics](https://github.com/bravecollective/sso-basics) 3.0.0
- Removed example login controller and HTML page.
- Changed EveAuthentication::$characterId type from string|int to int
