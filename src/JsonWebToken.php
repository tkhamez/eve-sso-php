<?php

declare(strict_types=1);

namespace Brave\Sso\Basics;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * Parse and verify a JSON Web Token.
 */
class JsonWebToken
{
    /**
     * @var AccessTokenInterface 
     */
    private $token;

    /**
     * @var JWS 
     */
    private $jws;

    /**
     * @var \stdClass 
     */
    private $payload;

    /**
     * @param AccessTokenInterface $token Must contain an EVE SSOv2 JSON Web Token
     * @throws \UnexpectedValueException
     */
    public function __construct(AccessTokenInterface $token)
    {
        $this->token = $token;

        $serializerManager = new JWSSerializerManager([new CompactSerializer()]);
        try {
            $this->jws = $serializerManager->unserialize($this->token->getToken());
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Could not parse token.', 1526220021);
        }

        // parse data
        $this->payload = json_decode($this->jws->getPayload());
        if ($this->payload === null || ! isset($this->payload->sub)) {
            throw new \UnexpectedValueException('Invalid token data.', 1526220022);
        }
    }

    /**
     * @param string $baseUrl The base URL for authorizing a client
     * @return bool
     */
    public function verifyIssuer(string $baseUrl): bool
    {
        if (strpos($baseUrl, $this->payload->iss) === false) {
            return false;
        }
        return true;
    }

    /**
     * @param array $publicKeys
     * @throws \LogicException If Elliptic Curve key type not supported by OpenSSL
     * @throws \UnexpectedValueException
     * @return bool
     */
    public function verifySignature(array $publicKeys): bool
    {
        $keys = [];
        foreach ($publicKeys as $key) {
            try {
                $keys[] = new JWK($key);
            } catch(\InvalidArgumentException $e) {
                throw new \UnexpectedValueException('Invalid public key.', 1526220024);
            }
        }
        $algorithmManager = new AlgorithmManager([new RS256(), new ES256(), new HS256()]);
        $jwsVerifier = new JWSVerifier($algorithmManager);
        try {
            $valid = $jwsVerifier->verifyWithKeySet($this->jws, new JWKSet($keys), 0);
        } catch(\InvalidArgumentException $e) {
            throw new \UnexpectedValueException('Could not verify token signature.', 1526220025);
        }
        if (! $valid) {
            throw new \UnexpectedValueException('Invalid token signature.', 1526220026);
        }
        
        return true;
    }

    public function getEveAuthentication(): EveAuthentication
    {
        $data = $this->payload;

        return new EveAuthentication(
            (int) str_replace('CHARACTER:EVE:', '', $data->sub),
            $data->name ?? '',
            $data->owner ?? '',
            $this->token,
            isset($data->scp) ? (is_string($data->scp) ? [$data->scp] : $data->scp) : []
        );
    }
}
