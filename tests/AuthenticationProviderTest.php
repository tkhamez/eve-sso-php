<?php

declare(strict_types=1);

namespace Test;

use Eve\Sso\AuthenticationProvider;
use Eve\Sso\InvalidGrantException;
use Exception;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;
use UnexpectedValueException;

class AuthenticationProviderTest extends TestCase
{
    private TestClient $client;

    private TestLogger $logger;

    private AuthenticationProvider $authenticationProvider;

    public function setUp(): void
    {
        $this->client = new TestClient();
        $options = [
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
            'urlMetadata' => 'https://localhost/.well-known/oauth-authorization-server',
            'urlAuthorize' => 'https://localhost/auth',
            'urlAccessToken' => 'https://localhost/token',
            'urlKeySet' => 'http://localhost/jwks',
            'urlRevoke' => 'http://localhost/revoke',
            'issuer' => 'localhost',
        ];
        $this->logger = new TestLogger();
        $this->authenticationProvider = new AuthenticationProvider(
            $options,
            [],
            $this->client,
            $this->logger
        );
    }

    public function testConstruct_MinimalOptions()
    {
        $this->client->setResponse(
            new Response(200, [], '{
                "issuer": "localhost",
                "authorization_endpoint": "https://localhost/auth",
                "token_endpoint": "https://localhost/token",
                "jwks_uri": "http://localhost/jwks",
                "revocation_endpoint": "http://localhost/revoke"
            }')
        );

        new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
        ], [], $this->client);

        $this->assertTrue(true); // no exception was thrown
    }

    public function testConstruct_Exception()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('At least one of the required options is not defined or empty.');

        new AuthenticationProvider([
            #'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
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
     * @throws Throwable
     */
    public function testGenerateState()
    {
        $this->assertMatchesRegularExpression(
            '/prefix[a-f0-9]{32}/i',
            $this->authenticationProvider->generateState('prefix')
        );
    }

    public function testBuildLoginUrl_MinimalOptions_RequestException()
    {
        $provider = new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
        ], [], $this->client, $this->logger);

        $this->client->setResponse(new TransferException('Error from Guzzle.'));

        try {
            $provider->buildLoginUrl('state123');
        } catch (UnexpectedValueException $e) {
            $this->assertSame(1526220041, $e->getCode());
            $this->assertSame('Failed to fetch metadata.', $e->getMessage());
            $this->assertSame('Error from Guzzle.', $e->getPrevious()->getMessage());
        }

        $this->assertSame(['Error from Guzzle.'], $this->logger->getMessages());
    }

    public function testBuildLoginUrl_MinimalOptions_InvalidDataException()
    {
        $provider = new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
        ], [], $this->client);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220042);
        $this->expectExceptionMessage('Missing entries from metadata URL.');

        $this->client->setResponse(new Response(200, [], '{}'));

        $provider->buildLoginUrl('state123');
    }

    public function testBuildLoginUrl_MinimalOptions_Ok()
    {
        $this->client->setResponse(
            new Response(200, [], '{
                "issuer": "localhost",
                "authorization_endpoint": "https://localhost/auth",
                "token_endpoint": "https://localhost/token",
                "jwks_uri": "http://localhost/jwks",
                "revocation_endpoint": "http://localhost/revoke"
            }')
        );

        $provider = new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
        ], [], $this->client);

        $provider->buildLoginUrl('state123');

        $this->assertTrue(true); // no exception was thrown
    }

    /**
     * @throws Exception
     */
    public function testBuildLoginUrl()
    {
        $url = $this->authenticationProvider->buildLoginUrl('state123');
        $this->assertStringContainsString('state=state123', $url);
    }

    public function testValidateAuthenticationV2_MinimalOptions_RequestException()
    {
        $provider = new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
        ], [], $this->client, $this->logger);

        $this->client->setResponse(new TransferException('Error from Guzzle.'));

        $this->expectExceptionMessage('Failed to fetch metadata.');

        $provider->validateAuthenticationV2('state1', 'state2', 'code');
    }

    public function testValidateAuthenticationV2_ExceptionWrongSessionState()
    {
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220012);
        $this->expectExceptionMessage('OAuth state mismatch.');

        $this->authenticationProvider->validateAuthenticationV2('state1', 'state2', 'code');
    }

    public function testValidateAuthenticationV2_ExceptionGetTokenError()
    {
        $this->client->setResponse(new Response(200, [], 'no json'));

        try {
            $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
        } catch (UnexpectedValueException $e) {
            $this->assertSame(1526220013, $e->getCode());
            $this->assertSame('Error when requesting the token.', $e->getMessage());
            $this->assertSame(
                'Invalid response received from Authorization Server. Expected JSON.',
                $e->getPrevious()->getMessage()
            );
        }

        $this->assertSame(
            ['Invalid response received from Authorization Server. Expected JSON.'],
            $this->logger->getMessages()
        );
    }

    /**
     * @throws Throwable
     */
    public function testValidateAuthenticationV2_ExceptionValidateJWTokenWrongIssuer()
    {
        list($token) = TestHelper::createTokenAndKeySet('invalid.host');
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}')
        );

        try {
            $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
        } catch (UnexpectedValueException $e) {
            $this->assertSame(1526220023, $e->getCode());
            $this->assertSame('Token issuer does not match.', $e->getMessage());
        }

        $this->assertSame(
            ["Issuer 'invalid.host' does not match 'localhost'"],
            $this->logger->getMessages()
        );
    }

    /**
     * @throws Throwable
     */
    public function testValidateAuthenticationV2_ExceptionWrongScopes()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}')
        );

        $this->authenticationProvider->setScopes(['scope1']);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220014);
        $this->expectExceptionMessage('Required scopes do not match.');

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws Throwable
     */
    public function testValidateAuthenticationV2_ExceptionPublicKeysGetError()
    {
        list($token) = TestHelper::createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new TransferException('Failed to parse public keys.', 1526220032)
        );

        try {
            $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
        } catch (UnexpectedValueException $e) {
            $this->assertSame(1526220031, $e->getCode());
            $this->assertSame('Failed to get public keys.', $e->getMessage());
            $this->assertSame('Failed to parse public keys.', $e->getPrevious()->getMessage());
        }

        $this->assertSame(['Failed to parse public keys.'], $this->logger->getMessages());
    }

    /**
     * @throws Throwable
     */
    public function testValidateAuthenticationV2_ExceptionPublicKeysParseError()
    {
        list($token) = TestHelper::createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], 'no json')
        );

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220032);
        $this->expectExceptionMessage('Failed to parse public keys.');

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws Throwable
     */
    public function testValidateAuthenticationV2_PublicKeysCache()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet(); // issuer = localhost

        $this->client->setResponse(
            // for getAccessToken()
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}'), // for SSO JWT key set
            // for getAccessToken()
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}')
        );

        $this->authenticationProvider->setScopes(['scope1', 'scope2']);
        $result1 = $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
        $result2 = $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');

        $this->assertSame(123, $result1->getCharacterId());
        $this->assertSame(123, $result2->getCharacterId());
    }

    /**
     * @throws Throwable
     */
    public function testValidateAuthenticationV2_Success()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet(); // issuer = localhost

        // set responses
        $this->client->setResponse(
            // for getAccessToken()
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}'),
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
     * @throws Throwable
     */
    public function testValidateAuthenticationV2_NoSignature()
    {
        list($token) = TestHelper::createTokenAndKeySet('localhost', 'CHARACTER:EVE:123', []);

        // set responses
        $this->client->setResponse(
            // for getAccessToken()
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}')
        );

        // run
        $this->authenticationProvider->setSignatureVerification(false);
        $result = $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');

        // verify
        $this->assertSame(123, $result->getCharacterId());
    }

    /**
     * @throws Throwable
     */
    public function testValidateAuthenticationV2SuccessIssuerWithHttps()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet(
            'https://localhost',
            'CHARACTER:EVE:123456',
            []
        );
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token) . '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}')
        );
        $result = $this->authenticationProvider->validateAuthenticationV2('state', 'state');
        $this->assertSame(123456, $result->getCharacterId());
    }

    /**
     * @throws InvalidGrantException
     */
    public function testRefreshAccessToken_MinimalOptions_RequestException()
    {
        $provider = new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
        ], [], $this->client, $this->logger);

        $token = new AccessToken([
            'access_token' => 'at',
            'refresh_token' => '',
            'expires' => 1349067601 // 2012-10-01 + 1
        ]);

        $this->client->setResponse(new TransferException('Error from Guzzle.'));

        $this->expectExceptionMessage('Failed to fetch metadata.');

        $provider->refreshAccessToken($token);
    }

    /**
     * @throws Throwable
     */
    public function testRefreshAccessToken_ServerException()
    {
        $this->client->setResponse(new Response(500));

        $token = new AccessToken([
            'access_token' => 'at',
            'refresh_token' => '',
            'expires' => 1349067601 // 2012-10-01 + 1
        ]);

        try {
            $this->authenticationProvider->refreshAccessToken($token);
        } catch (RuntimeException $e) {
            $this->assertSame(0, $e->getCode());
            $this->assertSame(
                'An OAuth server error was encountered that did not contain a JSON body',
                $e->getMessage()
            );
            $this->assertSame(
                'An OAuth server error was encountered that did not contain a JSON body',
                $e->getPrevious()->getMessage()
            );
        }
    }

    public function testRefreshAccessToken_IdentityProviderException()
    {
        $this->client->setResponse(new Response(400, [], '{ "error": "invalid_grant" }'));

        $token = new AccessToken([
            'access_token' => 'at',
            'refresh_token' => 'rt',
            'expires' => 1349067601 // 2012-10-01 + 1
        ]);

        try {
            $this->authenticationProvider->refreshAccessToken($token);
        } catch (InvalidGrantException $e) {
            $this->assertSame(0, $e->getCode());
            $this->assertSame('', $e->getMessage());
            $this->assertSame('invalid_grant', $e->getPrevious()->getMessage());
        }
    }

    /**
     * @throws Throwable
     */
    public function testRefreshAccessToken_NotExpired()
    {
        $token = new AccessToken([
            'access_token' => 'old-token',
            'refresh_token' => 're-tk',
            'expires' => time() + 10000
        ]);

        $this->assertSame(
            'old-token',
            $this->authenticationProvider->refreshAccessToken($token)->getToken()
        );
    }

    /**
     * @throws Throwable
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
     * @throws GuzzleException
     */
    public function testRevokeAccessToken_MinimalOptions_RequestException()
    {
        $provider = new AuthenticationProvider([
            'clientId'     => '123',
            'clientSecret' => 'abc',
            'redirectUri'  => 'https://localhost/callback',
        ], [], $this->client, $this->logger);

        $token = new AccessToken(['access_token' => 'at', 'refresh_token' => 'rt']);

        $this->client->setResponse(new TransferException('Error from Guzzle.'));

        $this->expectExceptionMessage('Failed to fetch metadata.');

        $provider->revokeRefreshToken($token);
    }

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
     * @throws Throwable
     */
    public function testRevokeAccessToken_Failure()
    {
        $this->client->setResponse(new Response(400));

        $token = new AccessToken(['access_token' => 'at', 'refresh_token' => 'rt']);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error revoking token: 400 Bad Request');

        $this->authenticationProvider->revokeRefreshToken($token);
    }

    /**
     * @throws Throwable
     */
    public function testRevokeAccessToken_OK()
    {
        $this->client->setResponse(new Response(200));

        $token = new AccessToken(['access_token' => 'at', 'refresh_token' => 'rt']);

        $this->authenticationProvider->revokeRefreshToken($token);

        $this->assertTrue(true); // did not throw an exception
    }
}
