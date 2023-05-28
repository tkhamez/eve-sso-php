<?php

declare(strict_types=1);

namespace Test;

use Eve\Sso\JsonWebToken;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;

class JsonWebTokenTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testConstructExceptionParseError()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220021);
        $this->expectExceptionMessage('Could not parse token.');

        $token = new AccessToken(['access_token' => 'string']);
        new JsonWebToken($token);
    }

    /**
     * @throws \Exception
     */
    public function testConstructExceptionInvalidData()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220022);
        $this->expectExceptionMessage('Invalid token data.');

        list($token) = TestHelper::createTokenAndKeySet('localhost', null);

        $token = new AccessToken(['access_token' => $token]);
        new JsonWebToken($token);
    }

    /**
     * @throws \Exception
     */
    public function testConstruct()
    {
        list($token) = TestHelper::createTokenAndKeySet();

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);

        $this->assertInstanceOf(JsonWebToken::class, $jws);
    }

    /**
     * @throws \Exception
     */
    public function testVerifyIssuer()
    {
        list($token) = TestHelper::createTokenAndKeySet('https://local.host');
        $accessToken = new AccessToken(['access_token' => $token]);
        $jwt = new JsonWebToken($accessToken);
        $this->assertFalse($jwt->verifyIssuer('https://other.host'));
        $this->assertTrue($jwt->verifyIssuer('https://local.host'));
        $this->assertTrue($jwt->verifyIssuer('local.host'));

        list($token2) = TestHelper::createTokenAndKeySet('local.host');
        $accessToken2 = new AccessToken(['access_token' => $token2]);
        $jwt2 = new JsonWebToken($accessToken2);
        $this->assertFalse($jwt2->verifyIssuer('other.host'));
        $this->assertFalse($jwt2->verifyIssuer('https://local.host'));
        $this->assertTrue($jwt2->verifyIssuer('local.host'));
    }

    /**
     * @throws \Exception
     */
    public function testVerifySignatureExceptionInvalidPublicKey()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220024);
        $this->expectExceptionMessage('Invalid public key.');

        list($token, $keySet) = TestHelper::createTokenAndKeySet();
        unset($keySet[0]['kty']);

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);
        $jws->verifySignature($keySet);
    }

    /**
     * @throws \Exception
     */
    public function testVerifySignatureExceptionSignatureError()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220025);
        $this->expectExceptionMessage('Could not verify token signature: There is no key in the key set.');

        list($token) = TestHelper::createTokenAndKeySet();

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);
        $jws->verifySignature([]);
    }

    /**
     * @throws \Exception
     */
    public function testVerifySignatureExceptionSignatureInvalid()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionCode(1526220026);
        $this->expectExceptionMessage('Invalid token signature.');

        list($token, $keySet) = TestHelper::createTokenAndKeySet();
        $keySet[0]['alg'] = 'unknown';
        
        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);
        $jws->verifySignature($keySet);
    }

    /**
     * @throws \Exception
     */
    public function testVerifySignature()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet();

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);
        
        $this->assertTrue($jws->verifySignature($keySet));
    }

    /**
     * @throws \Exception
     */
    public function testGetEveAuthentication()
    {
        list($token) = TestHelper::createTokenAndKeySet();

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);
        
        $auth = $jws->getEveAuthentication();
        
        $this->assertSame(123, $auth->getCharacterId());
        $this->assertSame('Name', $auth->getCharacterName());
        $this->assertSame('hash', $auth->getCharacterOwnerHash());
        $this->assertSame($token, $auth->getToken());
        $this->assertSame(['scope1', 'scope2'], $auth->getScopes());
    }
}
