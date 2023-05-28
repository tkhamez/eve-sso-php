<?php

declare(strict_types=1);

namespace Eve\Sso;

use Exception;
use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use League\OAuth2\Client\Token\AccessTokenInterface;
use LogicException;
use stdClass;
use UnexpectedValueException;

/**
 * Parse and verify a JSON Web Token.
 */
class JsonWebToken
{
    private AccessTokenInterface $token;

    private JWS $jws;

    private ?stdClass $payload;

    /**
     * @param AccessTokenInterface $token Must contain an EVE SSOv2 JSON Web Token
     * @throws UnexpectedValueException
     */
    public function __construct(AccessTokenInterface $token)
    {
        $this->token = $token;

        $serializerManager = new JWSSerializerManager([new CompactSerializer()]);
        try {
            $this->jws = $serializerManager->unserialize($this->token->getToken());
        } catch (Exception) {
            throw new UnexpectedValueException('Could not parse token.', 1526220021);
        }

        // parse data
        $this->payload = json_decode($this->jws->getPayload());
        if ($this->payload === null || !isset($this->payload->sub)) {
            throw new UnexpectedValueException('Invalid token data.', 1526220022);
        }
    }

    public function verifyIssuer(string $issuer): bool
    {
        // see https://github.com/ccpgames/sso-issues/issues/41

        $issuerWithHttps = $issuer;
        if (!str_starts_with($issuer, 'http')) {
            $issuerWithHttps = "https://$issuer";
        }

        return
            $this->payload->iss === $issuer ||
            $this->payload->iss === $issuerWithHttps;
    }

    /**
     * @param array $publicKeys
     * @throws LogicException If Elliptic Curve key type is not supported by OpenSSL
     * @throws UnexpectedValueException
     * @return bool
     */
    public function verifySignature(array $publicKeys): bool
    {
        $keyIds = [];
        $algorithms = [];
        foreach ($this->jws->getSignatures() as $signature) {
            $alg = $signature->getProtectedHeader()['alg'];
            if ($alg === 'RS256') {
                $keyIds[] = $signature->getProtectedHeader()['kid'];
                $algorithms[] = new RS256();
            }
        }

        $keys = [];
        foreach ($publicKeys as $publicKey) {
            if (!in_array($publicKey['kid'], $keyIds) || $publicKey['kid'] !== $this->payload->kid) {
                continue;
            }
            try {
                $keys[] = new JWK($publicKey);
            } catch(InvalidArgumentException) {
                throw new UnexpectedValueException('Invalid public key.', 1526220024);
            }
        }

        $algorithmManager = new AlgorithmManager($algorithms);
        $jwsVerifier = new JWSVerifier($algorithmManager);

        $valid = false;
        for ($i = 0; $i < count($this->jws->getSignatures()); $i++) {
            try {
                $valid = $jwsVerifier->verifyWithKeySet($this->jws, new JWKSet($keys), $i);
            } catch(InvalidArgumentException $e) {
                throw new UnexpectedValueException(
                    'Could not verify token signature: ' . $e->getMessage(), 1526220025
                );
            }
            if ($valid) {
                break;
            }
        }
        if (!$valid) {
            throw new UnexpectedValueException('Invalid token signature.', 1526220026);
        }

        return true;
    }

    public function getEveAuthentication(): EveAuthentication
    {
        $data = $this->payload;

        return new EveAuthentication(
            (int)str_replace('CHARACTER:EVE:', '', $data->sub),
            $data->name ?? '',
            $data->owner ?? '',
            $this->token,
            isset($data->scp) ? (is_string($data->scp) ? [$data->scp] : $data->scp) : []
        );
    }
}
