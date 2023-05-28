[![build](https://github.com/tkhamez/eve-sso-php/workflows/test/badge.svg)](https://github.com/tkhamez/eve-sso-php/actions)
[![Test Coverage](https://api.codeclimate.com/v1/badges/d607d04898a6f8500b99/test_coverage)](https://codeclimate.com/github/tkhamez/eve-sso-php/test_coverage)

# EVE SSO

Package supporting EVE SSO v2.

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
        // Required
        'clientId'       => 'your-EVE-app-client-ID',
        'clientSecret'   => 'your-EVE-app-secret-key',
        'redirectUri'    => 'https://your-callback.url',
        
        // Optional, these are the default values.
        'urlAuthorize'   => 'https://login.eveonline.com/v2/oauth/authorize',
        'urlAccessToken' => 'https://login.eveonline.com/v2/oauth/token',
        'urlKeySet'      => 'https://login.eveonline.com/oauth/jwks',
        'urlRevoke'      => 'https://login.eveonline.com/v2/oauth/revoke',
        'issuer'         => 'login.eveonline.com',
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
    $auth = $provider->validateAuthenticationV2($_GET['state'], $_SESSION['state'], $_GET['code']);
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
