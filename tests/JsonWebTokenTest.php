<?php

declare(strict_types=1);

namespace Test;

use Eve\Sso\JsonWebToken;
use Exception;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class JsonWebTokenTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testConstructExceptionParseError()
    {
        $token = new AccessToken(['access_token' => 'string']);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220021);
        $this->expectExceptionMessage('Could not parse token.');

        new JsonWebToken($token);
    }

    /**
     * @throws Exception
     */
    public function testConstructExceptionInvalidData()
    {
        list($token) = TestHelper::createTokenAndKeySet('localhost', null);

        $token = new AccessToken(['access_token' => $token]);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220022);
        $this->expectExceptionMessage('Invalid token data.');

        new JsonWebToken($token);
    }

    /**
     * @throws Exception
     */
    public function testConstructOk()
    {
        list($token) = TestHelper::createTokenAndKeySet();

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);

        $this->assertInstanceOf(JsonWebToken::class, $jws);
    }

    /**
     * @throws Exception
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
     * @throws Exception
     */
    public function testVerifySignatureExceptionInvalidPublicKey()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet();
        unset($keySet[0]['kty']);

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220024);
        $this->expectExceptionMessage('Invalid public key.');

        $jws->verifySignature($keySet);
    }

    /**
     * @throws Exception
     */
    public function testVerifySignatureExceptionSignatureError()
    {
        list($token) = TestHelper::createTokenAndKeySet();

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220025);
        $this->expectExceptionMessage('Could not verify token signature: There is no key in the key set.');

        $jws->verifySignature([]);
    }

    /**
     * @throws Exception
     */
    public function testVerifySignatureExceptionSignatureInvalid()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet();
        $keySet[0]['alg'] = 'unknown';

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionCode(1526220026);
        $this->expectExceptionMessage('Invalid token signature.');

        $jws->verifySignature($keySet);
    }

    /**
     * @throws Exception
     */
    public function testVerifySignatureOk()
    {
        list($token, $keySet) = TestHelper::createTokenAndKeySet();
        $keySet[] = ['kid' => 'something invalid'];

        $token = new AccessToken(['access_token' => $token]);
        $jws = new JsonWebToken($token);
        
        $this->assertTrue($jws->verifySignature($keySet));
    }

    /**
     * @throws Exception
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
