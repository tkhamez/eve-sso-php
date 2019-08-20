<?php declare(strict_types=1);

namespace Test;

use Brave\Sso\Basics\AuthenticationProvider;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Psr7\Response;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use League\OAuth2\Client\Provider\GenericProvider;
use PHPUnit\Framework\TestCase;

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

    public function setUp()
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

    public function testGetProvider()
    {
        $this->assertInstanceOf(GenericProvider::class, $this->authenticationProvider->getProvider());
    }

    /**
     * @throws \Exception
     */
    public function testGenerateState()
    {
        $this->assertRegExp('/prefix[a-f0-9]{32}/i', $this->authenticationProvider->generateState('prefix'));
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

    public function testValidateAuthenticationV2ExceptionWrongSessionState()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220012);
        $this->expectExceptionMessage('OAuth state mismatch.');

        $this->authenticationProvider->validateAuthenticationV2('state1', 'state2', 'code');
    }

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

        list($token, $keySet) = $this->createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}')
        );

        $this->authenticationProvider->setScopes(['scope1']);
        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    public function testValidateAuthenticationV2ExceptionValidateJWTokenParseError()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220021);
        $this->expectExceptionMessage('Could not parse token.');

        $this->client->setResponse(new Response(200, [], '{"access_token": "string"}'));

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionValidateJWTokenInvalidData()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220022);
        $this->expectExceptionMessage('Invalid token data.');

        list($token) = $this->createTokenAndKeySet('localhost', null);
        $this->client->setResponse(new Response(200, [], '{"access_token": ' . json_encode($token). '}'));

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

        list($token) = $this->createTokenAndKeySet('invalid.host');
        $this->client->setResponse(new Response(200, [], '{"access_token": ' . json_encode($token). '}'));

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionValidateJWTokenInvalidPublicKey()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220024);
        $this->expectExceptionMessage('Invalid public key.');

        list($token, $keySet) = $this->createTokenAndKeySet();
        unset($keySet[0]['kty']);
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}')
        );

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionValidateJWTokenSignatureError()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220025);
        $this->expectExceptionMessage('Could not verify token signature.');

        list($token) = $this->createTokenAndKeySet();
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], '{"keys": ' . json_encode([]) . '}')
        );

        $this->authenticationProvider->validateAuthenticationV2('state', 'state', 'code');
    }

    /**
     * @throws \Exception
     */
    public function testValidateAuthenticationV2ExceptionValidateJWTokenSignatureInvalid()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220026);
        $this->expectExceptionMessage('Invalid token signature.');

        list($token, $keySet) = $this->createTokenAndKeySet();
        $keySet[0]['alg'] = 'unknown';
        $this->client->setResponse(
            new Response(200, [], '{"access_token": ' . json_encode($token). '}'),
            new Response(200, [], '{"keys": ' . json_encode($keySet) . '}')
        );

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

        list($token) = $this->createTokenAndKeySet();
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

        list($token) = $this->createTokenAndKeySet();
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
        list($token, $keySet) = $this->createTokenAndKeySet();

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
    private function createTokenAndKeySet($issuer = 'localhost', $sub = 'CHARACTER:EVE:123'): array
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $algorithmManager = AlgorithmManager::create([new RS256()]);
        $jwsBuilder = new JWSBuilder(null, $algorithmManager);
        $payload = (string) json_encode([
            'scp' => ['scope1', 'scope2'],
            'sub' => $sub,
            'name' => 'Name',
            'owner' => 'hash',
            'exp' => time() + 3600,
            'iss' => $issuer,
        ]);
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => $jwk->get('alg')])
            ->build();
        $token = (new CompactSerializer())->serialize($jws);
        $keySet = [$jwk->toPublic()->jsonSerialize()];

        return [$token, $keySet];
    }
}
