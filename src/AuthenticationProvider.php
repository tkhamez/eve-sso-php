<?php

declare(strict_types=1);

namespace Eve\Sso;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use InvalidArgumentException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use LogicException;
use RuntimeException;
use UnexpectedValueException;

class AuthenticationProvider
{
    private bool $signatureVerification = true;

    private ?ClientInterface $httpClient;

    private GenericProvider $sso;

    /**
     * Scopes for EVE SSO login.
     *
     * @var string[]
     */
    private array $scopes = [];

    private string $clientId;

    private string $clientSecret;

    private string $keySetUri;

    private string $revokeUrl;

    private string $issuer;

    /**
     * Cache of JSON Web Key Set.
     */
    private array $keys = [];

    /**
     * Cache of well-known entries.
     */
    private array $metadata = [];

    /**
     * @param array $options See README.md
     * @param string[] $scopes Required ESI scopes.
     * @throws InvalidArgumentException If a required option is missing
     * @throws UnexpectedValueException If EVE SSO metadata could not be fetched.
     * @see ../README.md
     */
    public function __construct(
        array $options,
        array $scopes = [],
        ClientInterface $httpClient = null
    ) {
        $this->httpClient = $httpClient ?? new Client();

        $options = $this->validateOptions($options);

        $this->sso = new GenericProvider($options, ['httpClient' => $this->httpClient]);
        $this->setScopes($scopes);

        $this->clientId = (string)$options['clientId'];
        $this->clientSecret = (string)$options['clientSecret'];
        $this->keySetUri = (string)$options['urlKeySet'];
        $this->revokeUrl = (string)$options['urlRevoke'];
        $this->issuer = (string)$options['issuer'];
    }

    public function setProvider(GenericProvider $provider): void
    {
        $this->sso = $provider;
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

    public function setSignatureVerification(bool $flag): self
    {
        $this->signatureVerification = $flag;

        return $this;
    }

    /**
     * Handle and validate OAuth response data from SSO v2.
     *
     * @throws UnexpectedValueException For different errors during validation.
     * @throws LogicException If Elliptic Curve key type is not supported by OpenSSL
     * @see https://github.com/esi/esi-docs/blob/master/docs/sso/validating_eve_jwt.md
     */
    public function validateAuthenticationV2(
        string $requestState, 
        string $sessionState,
        string $code = ''
    ): EveAuthentication {
        // check OAuth state parameter
        if ($requestState !== $sessionState) {
            throw new UnexpectedValueException('OAuth state mismatch.', 1526220012);
        }

        // get token
        try {
            $token = $this->sso->getAccessToken('authorization_code', ['code' => $code]);
        } catch (Exception) {
            throw new UnexpectedValueException('Error when requesting the token.', 1526220013);
        }

        // parse and verify token
        $jws = new JsonWebToken($token);
        if (!$jws->verifyIssuer($this->issuer)) {
            throw new UnexpectedValueException('Token issuer does not match.', 1526220023);
        }

        if ($this->signatureVerification) {
            $jws->verifySignature($this->getPublicKeys());
        }

        $auth = $jws->getEveAuthentication();

        // verify scopes (user can manipulate the SSO login URL)
        if (!$this->verifyScopes($auth->getScopes())) {
            throw new UnexpectedValueException('Required scopes do not match.', 1526220014);
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
     * @throws Exception
     */
    public function generateState(string $statePrefix = ''): string
    {
        return $statePrefix . bin2hex(random_bytes(16));
    }

    /**
     * Refreshes the access token if necessary.
     *
     * @param AccessTokenInterface $existingToken
     * @return AccessTokenInterface A new object if the token was refreshed
     * @throws InvalidGrantException For "invalid_grant" error, i.e. invalid or revoked refresh token.
     * @throws RuntimeException For all other errors.
     */
    public function refreshAccessToken(AccessTokenInterface $existingToken): AccessTokenInterface
    {
        $newToken = null;
        if ($existingToken->getExpires() && $existingToken->hasExpired()) {
            try {
                $newToken = $this->sso->getAccessToken(
                    'refresh_token',
                    ['refresh_token' => (string)$existingToken->getRefreshToken()]
                );
            } catch (Exception $e) {
                if ($e instanceof IdentityProviderException && $e->getMessage() === 'invalid_grant') {
                    // invalid_grant = e. g. invalid or revoked refresh token
                    throw new InvalidGrantException();
                } else {
                    throw new RuntimeException($e->getMessage());
                }
            }
        }

        return $newToken ?? $existingToken;
    }

    /**
     * Revokes a refresh token. Only tested with EVE SSOv2.
     *
     * @param AccessTokenInterface $existingToken
     * @throws UnexpectedValueException If revoke URL is missing or token could not be revoked.
     * @throws GuzzleException Any other error.
     * @see https://github.com/esi/esi-docs/blob/master/docs/sso/revoking_refresh_tokens.md
     */
    public function revokeRefreshToken(AccessTokenInterface $existingToken): void
    {
        $response = $this->httpClient->request('POST', $this->revokeUrl, [
            'auth' => [$this->clientId, $this->clientSecret, 'basic'],
            'form_params' => [
                'token' => $existingToken->getRefreshToken(),
                'token_type_hint' => 'refresh_token'
            ],
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedValueException(
                'Error revoking token: ' . $response->getStatusCode() . ' ' . $response->getReasonPhrase()
            );
        }
    }

    /**
     * @throws InvalidArgumentException
     * @throws UnexpectedValueException
     */
    private function validateOptions(array $options): array
    {
        if (
            empty($options['clientId']) ||
            empty($options['clientSecret']) ||
            empty($options['redirectUri'])
        ) {
            throw new InvalidArgumentException('At least one of the required options is not defined or empty.');
        }

        if (
            empty($options['urlAuthorize']) ||
            empty($options['urlAccessToken']) ||
            empty($options['urlKeySet']) ||
            empty($options['urlRevoke']) ||
            empty($options['issuer'])
        ) {
            $metadata = $this->getMetadata();

            if (empty($options['urlAuthorize'])) {
                $options['urlAuthorize'] = $metadata['authorization_endpoint'];
            }
            if (empty($options['urlAccessToken'])) {
                $options['urlAccessToken'] = $metadata['token_endpoint'];
            }
            if (empty($options['urlKeySet'])) {
                $options['urlKeySet'] = $metadata['jwks_uri'];
            }
            if (empty($options['urlRevoke'])) {
                $options['urlRevoke'] = $metadata['revocation_endpoint'];
            }
            if (empty($options['issuer'])) {
                $options['issuer'] = $metadata['issuer'];
            }
        }

        // "urlResourceOwnerDetails" is required by the GenericProvider, but not used in this package.
        $options['urlResourceOwnerDetails'] = '';

        return $options;
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
     * @throws UnexpectedValueException
     */
    private function getMetadata(): array
    {
        if (!empty($this->metadata)) {
            return $this->metadata;
        }

        try {
            $response = $this->httpClient->request(
                'GET',
                'https://login.eveonline.com/.well-known/oauth-authorization-server'
            );
        } catch (GuzzleException) {
            throw new UnexpectedValueException('Failed to fetch metadata.', 1526220041);
        }

        $data = json_decode($response->getBody()->getContents(), true);
        if (
            $data === null ||
            !isset($data['authorization_endpoint']) ||
            !isset($data['token_endpoint']) ||
            !isset($data['jwks_uri']) ||
            !isset($data['revocation_endpoint']) ||
            !isset($data['issuer'])
        ) {
            throw new UnexpectedValueException('Missing entries from metadata URL.', 1526220042);
        }

        $this->metadata = [
            'authorization_endpoint' => $data['authorization_endpoint'],
            'token_endpoint'         => $data['token_endpoint'],
            'jwks_uri'               => $data['jwks_uri'],
            'revocation_endpoint'    => $data['revocation_endpoint'],
            'issuer'                 => $data['issuer'],
        ];

        return $this->metadata;
    }

    /**
     * @throws UnexpectedValueException
     */
    private function getPublicKeys(): array
    {
        if (!empty($this->keys)) {
            return $this->keys;
        }

        try {
            $response = $this->httpClient->request('GET', $this->keySetUri);
        } catch (GuzzleException) {
            throw new UnexpectedValueException('Failed to get public keys.', 1526220031);
        }

        $keySet = json_decode($response->getBody()->getContents(), true);
        if ($keySet === null || !isset($keySet['keys']) || !is_array($keySet['keys'])) {
            throw new UnexpectedValueException('Failed to parse public keys.', 1526220032);
        }

        $this->keys = $keySet['keys'];

        return $this->keys;
    }
}
