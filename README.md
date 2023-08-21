[![build](https://github.com/tkhamez/eve-sso-php/workflows/test/badge.svg)](https://github.com/tkhamez/eve-sso-php/actions)
[![Test Coverage](https://api.codeclimate.com/v1/badges/d607d04898a6f8500b99/test_coverage)](https://codeclimate.com/github/tkhamez/eve-sso-php/test_coverage)

# EVE Online SSO

PHP package supporting [EVE Online SSO v2](https://docs.esi.evetech.net/docs/sso/) (flow for web based applications)
including JWT signature verification.

## Install

To install the library via [Composer](http://getcomposer.org/), execute:

```shell
composer require tkhamez/eve-sso
```

## Example Usage

```php
// Initiate provider object
// (if you do not provide all optional URLs this will make a request to the metadata URL to
// get them).
try {
    $provider = new Eve\Sso\AuthenticationProvider(
        [
            // required
            'clientId'       => 'your-EVE-app-client-ID',
            'clientSecret'   => 'your-EVE-app-secret-key',
            'redirectUri'    => 'https://your-callback.url',
    
            // optional
            'urlAuthorize'   => 'https://login.eveonline.com/v2/oauth/authorize',
            'urlAccessToken' => 'https://login.eveonline.com/v2/oauth/token',
            'urlRevoke'      => 'https://login.eveonline.com/v2/oauth/revoke',
            'urlKeySet'      => 'https://login.eveonline.com/oauth/jwks',
            'issuer'         => 'login.eveonline.com',
            'urlMetadata' => 'https://login.eveonline.com/.well-known/oauth-authorization-server',
        ],
    
        // Add all required scopes.
        ['esi-mail.read_mail.v1', 'esi-skills.read_skills.v1'],
    
        // Optionally use your own HTTP client.
        httpClient: new GuzzleHttp\Client(),
    
        // Optionally add a logger to log exception that are caught from libraries
        // (any class implementing Psr\Log\LoggerInterface, the example uses monolog/monolog
        // which is not included in this package).
        logger: new Monolog\Logger('SSO', [new Monolog\Handler\StreamHandler('/path/to/logfile')])
    );
} catch (Exception $e) {
    echo $e->getMessage();
}

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
try {
    $auth = $provider->validateAuthenticationV2($_GET['state'], $_SESSION['state'], $_GET['code']);
} catch (Exception $e) {
    echo $e->getMessage();
}

// Store the token data somewhere
$refreshToken = $auth->getToken()->getRefreshToken();
$accessToken = $auth->getToken()->getToken();
$expires = $auth->getToken()->getExpires();
// ...
```

```php
// Refresh access token, if necessary.
$existingToken = new League\OAuth2\Client\Token\AccessToken([
    'refresh_token' => $refreshToken,
    'access_token' => $accessToken,
    'expires' => $expires,
]);
try {
    $token = $provider->refreshAccessToken($existingToken);
} catch (Exception $e) {
    echo $e->getMessage();
}
```

## Dev Env

```shell
docker build --tag eve-sso .
docker run -it --mount type=bind,source="$(pwd)",target=/app --workdir /app eve-sso /bin/sh
```
