[![Build Status](https://api.travis-ci.org/bravecollective/sso-basics.svg?branch=master)](https://travis-ci.org/bravecollective/sso-basics)

# sso-basics
Some super basic package for supporting EVE SSO

## Install

To install the bindings via [Composer](http://getcomposer.org/), add the following to `composer.json`:

```
{
    "repositories": [
        { "type": "git", "url": "https://github.com/bravecollective/sso-basics.git" }
    ],
    "require": {
        "bravecollective/sso-basics": "^1.0.0"
    }
}
```

Then run `composer install`

## Changelog

### 2.0.0 (unreleased)

- Support for EVE SSO v2
- Needs PHP 7.1+
- Needs ext-gmp PHP extension

### 1.0.0

- First stable release with support for EVE SSO v1.
- Needs PHP 5.6+
