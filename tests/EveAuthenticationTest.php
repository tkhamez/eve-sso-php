<?php

declare(strict_types=1);

namespace Test;

use Eve\Sso\EveAuthentication;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;

class EveAuthenticationTest extends TestCase
{
    /**
     * @var AccessToken
     */
    private $token;

    /**
     * @var EveAuthentication
     */
    private $auth;

    protected function setUp(): void
    {
        $this->token = new AccessToken(['access_token' => 'at']);
        $this->auth = new EveAuthentication(96061222, 'Name', 'hash', $this->token, ['scope1']);
    }

    public function testGetCharacterId()
    {
        $this->assertSame(96061222, $this->auth->getCharacterId());
    }

    public function testGetCharacterName()
    {
        $this->assertSame('Name', $this->auth->getCharacterName());
    }

    public function testGetCharacterOwnerHash()
    {
        $this->assertSame('hash', $this->auth->getCharacterOwnerHash());
    }

    public function testGetToken()
    {
        $this->assertSame($this->token, $this->auth->getToken());
    }

    public function testGetScopes()
    {
        $this->assertSame(['scope1'], $this->auth->getScopes());
    }

    /**
     * @throws \Exception
     */
    public function testJsonSerialize()
    {
        $this->assertSame([
            'characterId' => 96061222,
            'characterName' => 'Name',
            'token' => $this->token,
        ], $this->auth->jsonSerialize());
    }
}
