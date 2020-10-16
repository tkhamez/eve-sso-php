<?php

declare(strict_types=1);

namespace Test;

use Eve\Sso\AuthenticationProvider;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\GenericProvider;
use PHPUnit\Framework\ExpectationFailedException;
use PHPUnit\Framework\TestCase;
use SebastianBergmann\RecursionContext\InvalidArgumentException;

class AuthenticationProviderTest extends TestCase
{
    /**
     * @var TestClient
     */
    private $client;

    /**
     * @var AuthenticationProvider
     */
    private $authenticationProvider;

    public function setUp(): void
    {
        $this->client = new TestClient();
        $sso = new GenericProvider([
            'urlAuthorize' => 'http://localhost/auth',
            'urlAccessToken' => 'http://localhost/token',
            'urlResourceOwnerDetails' => 'http://localhost/owner',
        ]);
        $sso->setHttpClient($this->client);
        $this->authenticationProvider = new AuthenticationProvider($sso, [], 'http://localhost/jwks');
    }

    /**
     * @throws \Exception
     */
    public function testGetProvider()
    {
        $this->assertInstanceOf(GenericProvider::class, $this->authenticationProvider->getProvider());
    }

    /**
     * @throws \Exception
     */
    public function testGenerateState()
    {
        $this->assertMatchesRegularExpression(
            '/prefix[a-f0-9]{32}/i',
            $this->authenticationProvider->generateState('prefix')
        );
    }

    /**
     * @throws \UnexpectedValueException
     */
    public function testValidateAuthenticationStateException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526240073);
        $this->expectExceptionMessage('OAuth state mismatch.');

        $this->authenticationProvider->validateAuthentication('state1', 'state2');
    }

    /**
     * @throws \UnexpectedValueException
     */
    public function testValidateAuthenticationTokenException()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526240034);
        $this->expectExceptionMessage('Error when requesting the token.');

        $this->client->setResponse(new Response(500)); // for getAccessToken()

        $this->authenticationProvider->validateAuthentication('state', 'state', 'code');
    }

    /**
     * @throws \UnexpectedValueException
     */
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

    /**
     * @throws \UnexpectedValueException
     */
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

    /**
     * @throws \UnexpectedValueException
     */
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

    /**
     * @throws \UnexpectedValueException
     */
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

    /**
     * @throws \UnexpectedValueException
     */
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

    /**
     * @throws ExpectationFailedException
     * @throws InvalidArgumentException
     * @throws \UnexpectedValueException
     */
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

    /**
     * @throws \Exception
     */
    public function testBuildLoginUrl()
    {
        $url = $this->authenticationProvider->buildLoginUrl('state123');
        $this->assertStringContainsString('state=state123', $url);
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionWrongSessionState()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220012);
        $this->expectExceptionMessage('OAuth state mismatch.');

        $this->authenticationProvider->validateAuthenticationV2('state1', 'state2', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionGetTokenError()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220013);
        $this->expectExceptionMessage('Error when requesting the token.');

        $this->client->setResponse(new Response(200, [], 'no json'));

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionWrongScopes()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220014);
        $this->expectExceptionMessage('Required scopes do not match.');

        list($token, $keySet) = TestHelper::createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}')
        );

        $this->authenticationProvider->setScopes(['scope1']);
        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionValidateJWTokenWrongIssuer()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220023);
        $this->expectExceptionMessage('Token issuer does not match.');

        list($token) = TestHelper::createTokenAndKeySet('invalid.host');
        $this->client->setResponse(new Response(200, [], '{"access_token": ' . json_encode($token). '}'));

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionPublicKeysGetError()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220031);
        $this->expectExceptionMessage('Failed to get public keys.');

        list($token) = TestHelper::createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new TransferException('Failed to parse public keys.', 1526220032)
        );

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionPublicKeysParseError()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220032);
        $this->expectExceptionMessage('Failed to parse public keys.');

        list($token) = TestHelper::createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], 'no json')
        );

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2Success()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet();

        // set responses
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}'), // for getAccessToken()
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}') // for SSO JWT key set
        );

        // run
        $this->authenticationProvider->setScopes(['scope1', 'scope2']);
        $result = $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');

        // verify
        $this->assertSame(123, $result->getCharacterId());
        $this->assertSame('Name', $result->getCharacterName());
        $this->assertSame('hash', $result->getCharacterOwnerHash());
        $this->assertSame(['scope1', 'scope2'], $result->getScopes());
        $this->assertSame($token, $result->getToken()->getToken());
    }
}
