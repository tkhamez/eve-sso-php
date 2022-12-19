<?php

declare(strict_types=1);

namespace Test;

use Eve\Sso\AuthenticationProvider;
use Eve\Sso\InvalidGrantException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
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
        $options = [
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
            'urlAuthorize' => 'https://localhost/auth',
            'urlAccessToken' => 'https://localhost/token',
            'urlResourceOwnerDetails' => 'https://localhost/owner',
            'urlKeySet' => 'http://localhost/jwks',
            'urlRevoke' => 'http://localhost/revoke',
        ];
        $this->authenticationProvider = new AuthenticationProvider($options, []);
        $this->authenticationProvider->getProvider()->setHttpClient($this->client);
    }

    public function testConstruct_MinimalOptions()
    {
        new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
            'urlAuthorize' => 'https://localhost/auth',
            'urlAccessToken' => 'https://localhost/token',
            'urlResourceOwnerDetails' => '',
            'urlKeySet' => '',
            'urlRevoke' => 'http://localhost/revoke',
        ], []);

        $this->assertTrue(true); // no exception was thrown
    }

    public function testConstruct_Exception()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('At least one of the required options is not defined or empty.');

        new AuthenticationProvider([
            #'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
            'urlAuthorize' => 'https://localhost/auth',
            'urlAccessToken' => 'https://localhost/token',
            'urlResourceOwnerDetails' => 'https://localhost/owner',
            'urlKeySet' => 'http://localhost/jwks',
            'urlRevoke' => 'http://localhost/revoke',
        ], []);
    }

    public function testSetGetProvider()
    {
        $provider = new GenericProvider(
            ['urlAuthorize' => '', 'urlAccessToken' => '', 'urlResourceOwnerDetails' => '']
        );
        $this->authenticationProvider->setProvider($provider);
        $this->assertSame($provider, $this->authenticationProvider->getProvider());
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
    public function testValidateAuthenticationV2PublicKeysCache()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet(); // issuer = localhost

        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}'), // for getAccessToken()
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}'), // for SSO JWT key set

            new Response(200, [], '{"access_token": ' . json_encode($token) . '}') // for getAccessToken()
        );

        $this->authenticationProvider->setScopes(['scope1', 'scope2']);
        $result1 = $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
        $result2 = $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');

        $this->assertSame(123, $result1->getCharacterId());
        $this->assertSame(123, $result2->getCharacterId());
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2Success()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet(); // issuer = localhost

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

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2SuccessIssuerWithHttps()
    {
        // see https://github.com/ccpgames/sso-issues/issues/41

        list($token, $keySet) = TestHelper::createTokenAndKeySet('https://localhost', 'CHARACTER:EVE:123456', []);
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}')
        );
        $result = $this->authenticationProvider->validateAuthenticationV2('state', 'state');
        $this->assertSame(123456, $result->getCharacterId());
    }

    /**
     * @throws \Exception
     */
    public function testRefreshAccessToken_ServerException()
    {
        $this->client->setResponse(new Response(500));

        $token = new AccessToken([
            'access_token' => 'at',
            'refresh_token' => '',
            'expires' => 1349067601 // 2012-10-01 + 1
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('An OAuth server error ');

        $this->authenticationProvider->refreshAccessToken($token);
    }

    /**
     * @throws \Exception
     */
    public function testRefreshAccessToken_IdentityProviderException()
    {
        $this->client->setResponse(new Response(400, [], '{ "error": "invalid_grant" }'));

        $token = new AccessToken([
            'access_token' => 'at',
            'refresh_token' => 'rt',
            'expires' => 1349067601 // 2012-10-01 + 1
        ]);

        $this->expectException(InvalidGrantException::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('');

        $this->authenticationProvider->refreshAccessToken($token);
    }

    /**
     * @throws \Exception
     */
    public function testRefreshAccessToken_NotExpired()
    {
        $token = new AccessToken([
            'access_token' => 'old-token',
            'refresh_token' => 're-tk',
            'expires' => time() + 10000
        ]);

        $this->assertSame('old-token', $this->authenticationProvider->refreshAccessToken($token)->getToken());
    }

    /**
     * @throws \Exception
     */
    public function testRefreshAccessToken_NewToken()
    {
        $this->client->setResponse(new Response(
            200,
            [],
            '{"access_token": "new-token",
            "refresh_token": "",
            "expires": 1519933900}' // 03/01/2018 @ 7:51pm (UTC)
        ));

        $token = new AccessToken([
            'access_token' => 'old-token',
            'refresh_token' => '',
            'expires' => 1519933545 // 03/01/2018 @ 7:45pm (UTC)
        ]);

        $tokenResult = $this->authenticationProvider->refreshAccessToken($token);

        $this->assertNotSame($token, $tokenResult);
        $this->assertSame('new-token', $tokenResult->getToken());
    }

    /**
     * @throws \Throwable
     */
    public function testRevokeAccessToken_RequestError()
    {
        $this->client->setResponse(new TransferException('Error.', 543789));

        $token = new AccessToken(['access_token' => 'at', 'refresh_token' => 'rt']);

        $this->expectException(GuzzleException::class);
        $this->expectExceptionCode(543789);
        $this->expectExceptionMessage('Error.');

        $this->authenticationProvider->revokeRefreshToken($token);
    }

    /**
     * @throws \Throwable
     */
    public function testRevokeAccessToken_Failure()
    {
        $this->client->setResponse(new Response(400));

        $token = new AccessToken(['access_token' => 'at', 'refresh_token' => 'rt']);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error revoking token: 400 Bad Request');

        $this->authenticationProvider->revokeRefreshToken($token);
    }

    /**
     * @throws \Throwable
     */
    public function testRevokeAccessToken_OK()
    {
        $this->client->setResponse(new Response(200));

        $token = new AccessToken(['access_token' => 'at', 'refresh_token' => 'rt']);

        $this->authenticationProvider->revokeRefreshToken($token);

        $this->assertTrue(true); // did not throw an exception
    }
}
