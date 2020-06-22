[![Build Status](https://travis-ci.com/tkhamez/eve-sso.svg?branch=master)](https://travis-ci.com/tkhamez/eve-sso)

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
$_SESSION['state'] = $provider->generateState();
$loginUrl = $provider->buildLoginUrl($_SESSION['state']);
header("Location: $loginUrl");

// Callback URL
try {
    #$auth = $provider->validateAuthentication($_GET['state'], $_SESSION['state'], $_GET['code']);  // SSO v1
    $auth = $provider->validateAuthenticationV2($_GET['state'], $_SESSION['state'], $_GET['code']); // SSO v2
    print_r($auth->jsonSerialize());
} catch (Exception $e) {
    echo $e->getMessage();
}
```

## Changelog

### 1.0.0

- Forked and renamed from bravecollective/sso-basics
- Removed example login controller and HTML page.
