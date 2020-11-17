<?php

declare(strict_types=1);

namespace Eve\Sso;

use GuzzleHttp\Exception\GuzzleException;
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
     * @var string[]
     */
    private $scopes = [];

    /**
     * @var string|null
     */
    private $keySetUri;

    /**
     * @param GenericProvider $sso
     * @param string[] $scopes
     * @param string|null $keySetUrl URL of the JWT key set, required for SSO v2.
     * @see https://github.com/esi/esi-docs/blob/master/docs/sso/validating_eve_jwt.md
     */
    public function __construct(GenericProvider $sso, array $scopes = [], string $keySetUrl = null)
    {
        $this->sso = $sso;
        $this->setScopes($scopes);
        $this->keySetUri = $keySetUrl;
    }

    public function getProvider(): GenericProvider
    {
        return $this->sso;
    }

    /**
     * @param string[] $scopes
     */
    public function setScopes(array $scopes): self
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
     * @throws \UnexpectedValueException
     */
    public function validateAuthentication(
        string $requestState, 
        string $sessionState, 
        string $code = ''
    ): EveAuthentication {
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
     * @throws \UnexpectedValueException For different errors during validation.
     * @throws \LogicException If Elliptic Curve key type is not supported by OpenSSL
     * @throws \RuntimeException
     */
    public function validateAuthenticationV2(
        string $requestState, 
        string $sessionState,
        string $code = ''
    ): EveAuthentication {
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
        $jws = new JsonWebToken($token);
        if (! $jws->verifyIssuer($this->sso->getBaseAuthorizationUrl())) {
            throw new \UnexpectedValueException('Token issuer does not match.', 1526220023);
        }
        $jws->verifySignature($this->getPublicKeys());

        $auth = $jws->getEveAuthentication();

        // verify scopes (user can manipulate the SSO login URL)
        if (! $this->verifyScopes($auth->getScopes())) {
            throw new \UnexpectedValueException('Required scopes do not match.', 1526220014);
        }

        return $auth;
    }

    public function buildLoginUrl(string $state = ''): string
    {
        $options = [
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
        ];

        return $this->sso->getAuthorizationUrl($options);
    }

    /**
     * @throws \Exception
     */
    public function generateState(string $statePrefix = ''): string
    {
        return $statePrefix . bin2hex(random_bytes(16));
    }

    private function verifyScopes(array $scopes): bool
    {
        $diff1 = array_diff($this->scopes, $scopes);
        $diff2 = array_diff($scopes, $this->scopes);

        if (count($diff1) !== 0 || count($diff2) !== 0) {
            return false;
        }
        return true;
    }

    /**
     * @throws \RuntimeException
     * @throws \UnexpectedValueException
     */
    private function getPublicKeys(): array
    {
        $client = $this->sso->getHttpClient();

        try {
            $response = $client->request('GET', $this->keySetUri);
        } catch (GuzzleException $e) {
            throw new \UnexpectedValueException('Failed to get public keys.', 1526220031);
        }

        $keySet = json_decode($response->getBody()->getContents(), true);
        if ($keySet === null || ! isset($keySet['keys']) || ! is_array($keySet['keys'])) {
            throw new \UnexpectedValueException('Failed to parse public keys.', 1526220032);
        }

        return $keySet['keys'];
    }
}
