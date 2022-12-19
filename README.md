[![build](https://github.com/tkhamez/eve-sso-php/workflows/test/badge.svg)](https://github.com/tkhamez/eve-sso-php/actions)
[![Test Coverage](https://api.codeclimate.com/v1/badges/d607d04898a6f8500b99/test_coverage)](https://codeclimate.com/github/tkhamez/eve-sso-php/test_coverage)

# EVE SSO

Package supporting EVE SSO v1 and v2.

## Install

To install the bindings via [Composer](http://getcomposer.org/), execute:

```shell
composer require tkhamez/eve-sso
```

## Example Usage

```php
// Initiate provider object for login and callback URLs
$provider = new Eve\Sso\AuthenticationProvider(
    [
        'clientId'     => 'your-EVE-app-client-ID',
        'clientSecret' => 'your-EVE-app-secret-key',
        'redirectUri'  => 'https://your-callback.url',
        #'urlAuthorize'   => 'https://login.eveonline.com/oauth/authorize',    // SSO v1
        'urlAuthorize'    => 'https://login.eveonline.com/v2/oauth/authorize', // SSO v2
        #'urlAccessToken' => 'https://login.eveonline.com/oauth/token',    // SSO v1
        'urlAccessToken'  => 'https://login.eveonline.com/v2/oauth/token', // SSO v2
        'urlResourceOwnerDetails' => 'https://login.eveonline.com/oauth/verify', // only for SSO v1
        'urlKeySet' => 'https://login.eveonline.com/oauth/jwks', // only for SSO v2
        'urlRevoke' => 'https://login.eveonline.com/v2/oauth/revoke',
    ],
    ['esi-mail.read_mail.v1', 'esi-skills.read_skills.v1'], // add all required scopes
);

// Login URL
session_start();
$_SESSION['state'] = $provider->generateState();
$loginUrl = $provider->buildLoginUrl($_SESSION['state']);
header("Location: $loginUrl");

// Callback URL
session_start();
try {
    #$auth = $provider->validateAuthentication($_GET['state'], $_SESSION['state'], $_GET['code']);  // SSO v1
    $auth = $provider->validateAuthenticationV2($_GET['state'], $_SESSION['state'], $_GET['code']); // SSO v2
    print_r($auth->jsonSerialize());
} catch (Exception $e) {
    echo $e->getMessage();
}
```

## Dev Env

```shell
docker build --tag eve-sso .
docker run -it --mount type=bind,source="$(pwd)",target=/app --workdir /app eve-sso /bin/sh
```

Run tests with coverage:
```shell
XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-html coverage
```

## Changelog

### 3.0.0

- Changed constructor parameters of AuthenticationProvider class, see above.
- Added AuthenticationProvider::setProvider() method
- Added AuthenticationProvider::refreshAccessToken() method
- Added AuthenticationProvider::revokeRefreshToken() method
- The JSON Web Key Set is now cached.

### 2.0.2

- Update PHP requirement to include version 8 (^7.3|^8.0).

### 2.0.1

- Fix: Require PHP gmp extension (key verification fails without it).

### 2.0.0

- Raised minimum PHP version to 7.3.
- Updated Guzzle HTTP client to ^7.2 (from ^6.3).

### 1.0.0

- Forked and renamed from [bravecollective/sso-basics](https://github.com/bravecollective/sso-basics) 3.0.0
- Removed example login controller and HTML page.
- Changed EveAuthentication::$characterId type from string|int to int
