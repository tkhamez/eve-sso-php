[![Latest Stable Version](http://poser.pugx.org/tkhamez/eve-sso/v)](https://packagist.org/packages/tkhamez/eve-sso) 
[![Total Downloads](http://poser.pugx.org/tkhamez/eve-sso/downloads)](https://packagist.org/packages/tkhamez/eve-sso) 
[![License](http://poser.pugx.org/tkhamez/eve-sso/license)](https://packagist.org/packages/tkhamez/eve-sso) 
[![PHP Version Require](http://poser.pugx.org/tkhamez/eve-sso/require/php)](https://packagist.org/packages/tkhamez/eve-sso)
[![build](https://github.com/tkhamez/eve-sso-php/workflows/test/badge.svg)](https://github.com/tkhamez/eve-sso-php/actions)

# EVE SSO for PHP

A PHP library supporting [EVE Online SSO v2](https://developers.eveonline.com/docs/services/sso/) 
for web applications including JWT signature verification.

## Install

To install the library via [Composer](http://getcomposer.org/), execute:

```shell
composer require tkhamez/eve-sso
```

## Example Usage

These examples do not include error handling. Most methods throw exceptions which should be caught.

```php
// Initiate the provider object.
$provider = new Eve\Sso\AuthenticationProvider(
    [
        // Required.
        'clientId'       => 'your-EVE-app-client-ID',
        'clientSecret'   => 'your-EVE-app-secret-key',
        'redirectUri'    => 'https://your-callback.url',

        // Optional. If you do not provide all URLs, a request will be made
        // to the metadata URL to get them.
        'urlAuthorize'   => 'https://login.eveonline.com/v2/oauth/authorize',
        'urlAccessToken' => 'https://login.eveonline.com/v2/oauth/token',
        'urlRevoke'      => 'https://login.eveonline.com/v2/oauth/revoke',
        'urlKeySet'      => 'https://login.eveonline.com/oauth/jwks',
        'issuer'         => 'https://login.eveonline.com',
        'urlMetadata'    => 'https://login.eveonline.com/.well-known/oauth-authorization-server',
    ],

    // Optionally, add all required scopes.
    ['esi-mail.read_mail.v1', 'esi-skills.read_skills.v1'],

    // Optionally, use your own HTTP client.
    httpClient: new GuzzleHttp\Client(),

    // Optionally add a logger to log exceptions that are caught from libraries
    // (any class implementing Psr\Log\LoggerInterface, the example uses monolog/monolog
    // which is not included in this package).
    logger: new Monolog\Logger('SSO', [new Monolog\Handler\StreamHandler('/path/to/logfile')])
);

// Optionally disable signature verification.
$provider->setSignatureVerification(false);
```

```php
// Login URL
session_start();
$_SESSION['state'] = $provider->generateState();
$loginUrl = $provider->buildLoginUrl($_SESSION['state']);
header("Location: $loginUrl");
```

```php
// Callback URL
session_start();
$eveAuthentication = $provider->validateAuthenticationV2(
    $_GET['state'] ?? '', 
    $_SESSION['state'] ?? '', 
    $_GET['code'] ?? '',
);
unset($_SESSION['state']);

$characterId = $eveAuthentication->getCharacterId();
$refreshToken = $eveAuthentication->getToken()->getRefreshToken();
$accessToken = $eveAuthentication->getToken()->getToken();
$expires = $eveAuthentication->getToken()->getExpires();
// ... store the token data somewhere together with the character ID.
```

```php
// Refreshes access token, if necessary.
$existingToken = new League\OAuth2\Client\Token\AccessToken([
    'refresh_token' => $refreshToken,
    'access_token' => $accessToken,
    'expires' => $expires,
]);
$validToken = $provider->refreshAccessToken($existingToken);
```

## Development Environment

```shell
docker build --tag eve-sso .
docker run -it --mount type=bind,source="$(pwd)",target=/app --workdir /app eve-sso /bin/sh
```
