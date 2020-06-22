<?php

declare(strict_types=1);

namespace Test;

use Eve\Sso\EveAuthentication;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;

class EveAuthenticationTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testJsonSerialize()
    {
        $token = new AccessToken(['access_token' => 'at']);
        $auth = new EveAuthentication(96061222, 'Name', 'hash', $token);
        $this->assertSame([
            'characterId' => 96061222,
            'character_name' => 'Name',
            'token' => $token,
        ], $auth->jsonSerialize());
    }
}
