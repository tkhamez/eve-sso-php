<?php

declare(strict_types=1);

namespace Test;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

class TestHelper
{
    /**
     * @throws \Exception
     */
    public static function createTokenAndKeySet($issuer = 'localhost', $sub = 'CHARACTER:EVE:123'): array
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        $algorithmManager = new AlgorithmManager([new RS256()]);
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
