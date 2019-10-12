[![Build Status](https://api.travis-ci.org/bravecollective/sso-basics.svg?branch=master)](https://travis-ci.org/bravecollective/sso-basics)

# sso-basics
Some super basic package for supporting EVE SSO v1 and v2.

## Install

To install the bindings via [Composer](http://getcomposer.org/), execute:

```
composer require bravecollective/sso-basics
```

### SSO Login page

To use the exemplary SSO login page, you need [bravecollective/web-ui](https://github.com/bravecollective/web-ui), 
which contains the required CSS and images.

## Changelog

### 2.1.0

- Added JsonWebToken class
- Using strict types now

### 2.0.0

- Support for EVE SSO v2
- Needs PHP 7.1+
- Needs gmp and mbstring PHP extensions
- EveAuthentication class: The $token type hint has been changed from `ResourceOwnerAccessTokenInterface`
  to `AccessTokenInterface` because the ID is not added anyway and `League\OAuth2\Client\Provider::getAccessToken()`,
  from which this object originates, declares the same return type.

### 1.0.0

- First stable release with support for EVE SSO v1.
- Needs PHP 5.6+
