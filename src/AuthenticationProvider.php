<?php declare(strict_types=1);

namespace Brave\Sso\Basics;

use GuzzleHttp\Exception\GuzzleException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use League\OAuth2\Client\Provider\GenericProvider;

class AuthenticationProvider
{
    /**
     * @var GenericProvider
     */
    private $sso;

    /**
     * Scopes for EVE SSO login.
     *
     * @var array
     */
    private $scopes = [];

    /**
     * @var string|null
     */
    private $keySetUri;

    /**
     *
     * @param GenericProvider $sso
     * @param array $scopes
     * @param string $keySetUrl URL of the JWT key set, required for SSO v2.
     * @see https://github.com/esi/esi-docs/blob/master/docs/sso/validating_eve_jwt.md
     */
    public function __construct(GenericProvider $sso, array $scopes = [], $keySetUrl = null)
    {
        $this->sso = $sso;
        $this->setScopes($scopes);
        $this->keySetUri = $keySetUrl;
    }

    /**
     * @return GenericProvider
     */
    public function getProvider()
    {
        return $this->sso;
    }

    /**
     * @param array $scopes
     * @return $this
     */
    public function setScopes(array $scopes)
    {
        foreach ($scopes as $scope) {
            if ($scope !== '') {
                $this->scopes[] = $scope;
            }
        }

        return $this;
    }

    /**
     * Handle and validate OAuth response data
     *
     * @param string $requestState
     * @param string $sessionState
     * @param string $code
     * @return EveAuthentication
     * @throws \UnexpectedValueException
     */
    public function validateAuthentication($requestState, $sessionState, $code = '')
    {
        // check OAuth state parameter
        if ($requestState !== $sessionState) {
            throw new \UnexpectedValueException('OAuth state mismatch.', 1526240073);
        }

        // get token(s)
        try {
            $token = $this->sso->getAccessToken('authorization_code', [
                'code' => $code
            ]);
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Error when requesting the token.', 1526240034);
        }

        // get resource owner (character ID etc.)
        $resourceOwner = null;
        try {
            $resourceOwner = $this->sso->getResourceOwner($token);
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Error obtaining resource owner.', 1526240015);
        }

        // verify result
        $verify = $resourceOwner !== null ? $resourceOwner->toArray() : null;
        if (! is_array($verify) || ! isset($verify['CharacterID'])) {
            throw new \UnexpectedValueException('Error obtaining Character ID.', 1526239971);
        }

        // verify scopes (user can manipulate the SSO login URL)
        $scopes = isset($verify['Scopes']) ? $verify['Scopes'] : '';
        $scopeList = $scopes !== '' ? explode(' ', $scopes) : [];

        if (! $this->verifyScopes($scopeList)) {
            throw new \UnexpectedValueException('Required scopes do not match.', 1526239938);
        }

        return new EveAuthentication(
            $verify['CharacterID'],
            isset($verify['CharacterName']) ? $verify['CharacterName'] : '',
            isset($verify['CharacterOwnerHash']) ? $verify['CharacterOwnerHash'] : '',
            $token,
            $scopeList
        );
    }

    /**
     * Handle and validate OAuth response data from SSO v2.
     *
     * @param $requestState
     * @param $sessionState
     * @param string $code
     * @return EveAuthentication
     * @throws \UnexpectedValueException
     */
    public function validateAuthenticationV2($requestState, $sessionState, $code = '')
    {
        // check OAuth state parameter
        if ($requestState !== $sessionState) {
            throw new \UnexpectedValueException('OAuth state mismatch.', 1526220012);
        }

        // get token
        try {
            $token = $this->sso->getAccessToken('authorization_code', ['code' => $code]);
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Error when requesting the token.', 1526220013);
        }

        // parse and verify token
        $data = $this->validateJWToken($token->getToken());

        // verify scopes (user can manipulate the SSO login URL)
        $scopeList = isset($data->scp) ? (is_string($data->scp) ? [$data->scp] : $data->scp) : [];
        if (! $this->verifyScopes($scopeList)) {
            throw new \UnexpectedValueException('Required scopes do not match.', 1526220014);
        }

        return new EveAuthentication(
            (int) str_replace('CHARACTER:EVE:', '', $data->sub),
            $data->name,
            $data->owner,
            $token,
            $scopeList
        );
    }

    /**
     * @param string $state
     * @return string
     */
    public function buildLoginUrl($state = '')
    {
        $options = [
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
        ];

        $url = $this->sso->getAuthorizationUrl($options);
        return $url;
    }

    /**
     * @param string $statePrefix
     * @return string
     * @throws \Exception
     */
    public function generateState($statePrefix = '')
    {
        return $statePrefix . bin2hex(random_bytes(16));
    }

    /**
     * @param array
     * @return bool
     */
    private function verifyScopes(array $scopes)
    {
        $diff1 = array_diff($this->scopes, $scopes);
        $diff2 = array_diff($scopes, $this->scopes);

        if (count($diff1) !== 0 || count($diff2) !== 0) {
            return false;
        }
        return true;
    }

    /**
     * @param string $token
     * @return \stdClass
     * @throws \UnexpectedValueException
     */
    private function validateJWToken($token)
    {
        $serializerManager = JWSSerializerManager::create([new CompactSerializer()]);
        try {
            $jws = $serializerManager->unserialize($token);
        } catch (\Exception $e) {
            throw new \UnexpectedValueException('Could not parse token.', 1526220021);
        }

        // parse data
        $payload = json_decode($jws->getPayload());
        if ($payload === null || ! isset($payload->sub) || ! isset($payload->name) || ! isset($payload->owner)) {
            throw new \UnexpectedValueException('Invalid token data.', 1526220022);
        }

        // verify issuer
        if (strpos($this->sso->getBaseAuthorizationUrl(), $payload->iss) === false) {
            throw new \UnexpectedValueException('Token issuer does not match.', 1526220023);
        }

        // verify signature
        $keys = [];
        foreach ($this->getPublicKeys() as $key) {
            try {
                $keys[] = new JWK($key);
            } catch(\InvalidArgumentException $e) {
                throw new \UnexpectedValueException('Invalid public key.', 1526220024);
            }
        }
        $algorithmManager = AlgorithmManager::create([new RS256(), new ES256(), new HS256()]);
        $jwsVerifier = new JWSVerifier($algorithmManager);
        try {
            $valid = $jwsVerifier->verifyWithKeySet($jws, new JWKSet($keys), 0);
        } catch(\InvalidArgumentException $e) {
            throw new \UnexpectedValueException('Could not verify token signature.', 1526220025);
        }
        if (! $valid) {
            throw new \UnexpectedValueException('Invalid token signature.', 1526220026);
        }

        return $payload;
    }

    /**
     * @return array
     * @throws \UnexpectedValueException
     */
    private function getPublicKeys()
    {
        $client = $this->sso->getHttpClient();

        try {
            $response = $client->request('GET', $this->keySetUri);
        } catch (GuzzleException $e) {
            throw new \UnexpectedValueException('Failed to get public keys.', 1526220031);
        }

        $keySet = json_decode($response->getBody()->getContents(), true);
        if ($keySet === null) {
            throw new \UnexpectedValueException('Failed to parse public keys.', 1526220032);
        }

        return $keySet['keys'];
    }
}
