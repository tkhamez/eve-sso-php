[![build](https://github.com/tkhamez/eve-sso/workflows/test/badge.svg)](https://github.com/tkhamez/eve-sso/actions)

# EVE SSO

Package supporting EVE SSO v1 and v2.

## Install

To install the bindings via [Composer](http://getcomposer.org/), execute:

```
composer require tkhamez/eve-sso
```

## Example Usage

```php
$provider = new Eve\Sso\AuthenticationProvider(
    new League\OAuth2\Client\Provider\GenericProvider([
        'clientId'     => 'your-EVE-app-client-ID',
        'clientSecret' => 'your-EVE-app-secret-key',
        'redirectUri'  => 'https://your-callback.url',
        #'urlAuthorize'   => 'https://login.eveonline.com/oauth/authorize',    // SSO v1
        'urlAuthorize'    => 'https://login.eveonline.com/v2/oauth/authorize', // SSO v2
        #'urlAccessToken' => 'https://login.eveonline.com/oauth/token',    // SSO v1
        'urlAccessToken'  => 'https://login.eveonline.com/v2/oauth/token', // SSO v2
        'urlResourceOwnerDetails' => 'https://login.eveonline.com/oauth/verify', // only used for SSO v1
    ]),
    ['esi-mail.read_mail.v1', 'esi-skills.read_skills.v1'], // add all required scopes
    'https://login.eveonline.com/oauth/jwks' // only used for SSO v2
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

## Changelog

### next

Cache JSON Web Key Set.

### 2.0.2

Update PHP requirement to include version 8 (^7.3|^8.0).

### 2.0.1

- Fix: Require PHP gmp extension (key verification fails without it).

### 2.0.0

- Raised minimum PHP version to 7.3.
- Updated Guzzle HTTP client to ^7.2 (from ^6.3).

### 1.0.0

- Forked and renamed from [bravecollective/sso-basics](https://github.com/bravecollective/sso-basics) 3.0.0
- Removed example login controller and HTML page.
- Changed EveAuthentication::$characterId type from string|int to int
