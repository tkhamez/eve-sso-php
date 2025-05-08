# Changelog

## 6.0.0

Breaking changes:
- Fix: Reset scopes if setScopes() is called a second time instead of adding new scopes.

Other changes:
- Fix: Catch \Throwable instead of \Exception from AbstractProvider->getAccessToken().

## 5.1.0

June 1, 2024

- Replaced abandoned web-token/* packages with web-token/jwt-library.

## 5.0.0

January 26, 2024

- Dropped PHP 8.0 support.

## 4.1.1

October 19, 2023

- Improved "issuer" validation.

## 4.1.0

August 20, 2023

- Added optional PSR-3 logger to log exceptions that are caught from libraries (pass it to the 
  AuthenticationProvider constructor).
- Added original exception to raised exceptions, if applicable.
- Added metadata URL to configuration options (optional).

## 4.0.0

May 28, 2023

Breaking changes:

- Dropped PHP 7 support, minimum require PHP version is now 8.0.0.
- Removed support for EVE SSO v1, see also
  [SSO Endpoint Deprecations](https://developers.eveonline.com/blog/article/sso-endpoint-deprecations-2).
- EveAuthentication::jsonSerialize: Renamed `character_name` to `characterName`.
- AuthenticationProvider::__construct can now also throw an UnexpectedValueException.
- Removed libraries web-token/jwt-signature-algorithm-ecdsa and web-token/jwt-signature-algorithm-hmac and moved
  web-token/jwt-key-mgmt to require-dev.

Other changes:

- Some entries of the options array from AuthenticationProvider::construct are now optional (see 
  [README.md](README.md)) and have default values that are fetched from the EVE SSO metadata URL if they are 
  not provided.
- Added `issuer` to options array from AuthenticationProvider::construct (optional).
- Added optional $httpClient parameter to AuthenticationProvider::__construct.
- Added ability to disable signature verification (AuthenticationProvider::setSignatureVerification). It's 
  enabled by default.
- Improved signature verification.

## 3.0.0

Oct 17, 2021

- Changed constructor parameters of AuthenticationProvider class, see [README.md](README.md).
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
