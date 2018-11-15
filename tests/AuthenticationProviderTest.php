<?php
namespace Brave\Sso\Basics;

require_once 'TestClient.php';

use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\GenericProvider;

class AuthenticationProviderTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var TestClient
     */
    private $client;

    /**
     * @var AuthenticationProvider
     */
    private $authenticationProvider;

    public function setUp()
    {
        $this->client = new TestClient();
        $sso = new GenericProvider([
            'urlAuthorize' => 'http://localhost/auth',
            'urlAccessToken' => 'http://localhost/token',
            'urlResourceOwnerDetails' => 'http://localhost/owner',
        ]);
        $sso->setHttpClient($this->client);
        $this->authenticationProvider = new AuthenticationProvider($sso);
    }

    public function testValidateAuthenticationStateException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526240073);
        $this->expectExceptionMessage('OAuth state mismatch.');

        $this->authenticationProvider->validateAuthentication('state1', 'state2');
    }

    public function testValidateAuthenticationTokenException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526240034);
        $this->expectExceptionMessage('Error when requesting the token.');

        $this->client->setResponse(new Response(500)); // for getAccessToken()

        $this->authenticationProvider->validateAuthentication('state', 'state', 'code');
    }

    public function testValidateAuthenticationResourceOwnerException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526240015);
        $this->expectExceptionMessage('Error obtaining resource owner.');

        $this->client->setResponse(
            new Response(200, [], '{"access_token": "token"}'), // for getAccessToken()
            new Response(500) // for getResourceOwner
        );

        $this->authenticationProvider->validateAuthentication('state', 'state', 'code');
    }

    public function testValidateAuthenticationCharacterException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526239971);
        $this->expectExceptionMessage('Error obtaining Character ID.');

        $this->client->setResponse(
            new Response(200, [], '{"access_token": "token"}'), // for getAccessToken()
            new Response(200, [], '{"invalid": true}') // for getResourceOwner()
        );

        $this->authenticationProvider->validateAuthentication('state', 'state', 'code');
    }

    public function testValidateAuthenticationScopeExceptionWrongScope()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526239938);
        $this->expectExceptionMessage('Required scopes do not match.');

        $this->client->setResponse(
            new Response(200, [], '{"access_token": "token"}'), // for getAccessToken()
            new Response(200, [], '{
                "CharacterID": 123,
                "CharacterName": "Name",
                "CharacterOwnerHash": "hash",
                "Scopes": "scope1"
            }') // for getResourceOwner()
        );
        $this->authenticationProvider->setScopes(['scope2']);

        $this->authenticationProvider->validateAuthentication('state', 'state', 'code');
    }

    public function testValidateAuthenticationScopeExceptionMissingScope()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526239938);
        $this->expectExceptionMessage('Required scopes do not match.');

        $this->client->setResponse(
            new Response(200, [], '{"access_token": "token"}'), // for getAccessToken()
            new Response(200, [], '{
                "CharacterID": 123,
                "CharacterName": "Name",
                "CharacterOwnerHash": "hash",
                "Scopes": "scope1 scope2"
            }') // for getResourceOwner()
        );
        $this->authenticationProvider->setScopes(['scope1']);

        $this->authenticationProvider->validateAuthentication('state', 'state', 'code');
    }

    public function testValidateAuthenticationScopeExceptionAdditionalScope()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526239938);
        $this->expectExceptionMessage('Required scopes do not match.');

        $this->client->setResponse(
            new Response(200, [], '{"access_token": "token"}'), // for getAccessToken()
            new Response(200, [], '{
                "CharacterID": 123,
                "CharacterName": "Name",
                "CharacterOwnerHash": "hash",
                "Scopes": "scope1"
            }') // for getResourceOwner()
        );
        $this->authenticationProvider->setScopes(['scope1', 'scope2']);

        $this->authenticationProvider->validateAuthentication('state', 'state', 'code');
    }

    public function testValidateAuthenticationSuccess()
    {
        $this->client->setResponse(
            new Response(200, [], '{"access_token": "token"}'), // for getAccessToken()
            new Response(200, [], '{
                "CharacterID": 123,
                "CharacterName": "Name",
                "CharacterOwnerHash": "hash",
                "Scopes": "scope1 scope2"
            }') // for getResourceOwner()
        );
        $this->authenticationProvider->setScopes(['scope1', 'scope2']);

        $result = $this->authenticationProvider->validateAuthentication('state', 'state', 'code');

        $this->assertSame(123, $result->getCharacterId());
        $this->assertSame('Name', $result->getCharacterName());
        $this->assertSame('hash', $result->getCharacterOwnerHash());
        $this->assertSame(['scope1', 'scope2'], $result->getScopes());
        $this->assertSame('token', $result->getToken()->getToken());
    }

    public function testBuildLoginUrl()
    {
        $url = $this->authenticationProvider->buildLoginUrl('state123');
        $this->assertContains('state=state123', $url);
    }
}
