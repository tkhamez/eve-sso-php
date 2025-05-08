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
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;
use UnexpectedValueException;

class AuthenticationProvider
{
    private bool $signatureVerification = true;

    private ?GenericProvider $sso = null;

    /**
     * @var array<string, string>
     */
    private array $options;

    /**
     * Scopes for EVE SSO login.
     *
     * @var string[]
     */
    private array $scopes;

    private ?string $clientId = null;

    private ?string $clientSecret = null;

    private string $metadataUrl = 'https://login.eveonline.com/.well-known/oauth-authorization-server';

    private ?string $keySetUri = null;

    private ?string $revokeUrl = null;

    private ?string $issuer = null;

    /**
     * Cache of JSON Web Key Set.
     */
    private array $keys = [];

    /**
     * @param array $options See README.md
     * @param string[] $scopes Required ESI scopes.
     * @throws InvalidArgumentException If a required option is missing
     * @see ../README.md
     */
    public function __construct(
        array                             $options,
        array                             $scopes = [],
        private ?ClientInterface          $httpClient = null,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->httpClient = $httpClient ?? new Client();

        if (
            empty($options['clientId']) ||
            empty($options['clientSecret']) ||
            empty($options['redirectUri'])
        ) {
            throw new InvalidArgumentException('At least one of the required options is not defined or empty.');
        }

        $this->options = $options;
        $this->setScopes($scopes);
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
        $this->scopes = [];

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
     * @throws LogicException If OpenSSL does not support the elliptic curve key type.
     * @see https://github.com/esi/esi-docs/blob/master/docs/sso/validating_eve_jwt.md
     */
    public function validateAuthenticationV2(
        string $requestState, 
        string $sessionState,
        string $code = ''
    ): EveAuthentication {
        $this->setOptionsAndSsoProvider();

        // check OAuth state parameter
        if ($requestState !== $sessionState) {
            throw new UnexpectedValueException('OAuth state mismatch.', 1526220012);
        }

        // get token
        try {
            $token = $this->sso->getAccessToken('authorization_code', ['code' => $code]);
        } catch (Throwable $e) {
            $this->logger?->error($e->getMessage(), ['exception' => $e]);
            throw new UnexpectedValueException('Error when requesting the token.', 1526220013, $e);
        }

        // parse and verify token
        $jws = new JsonWebToken($token, $this->logger);
        if (!$jws->verifyIssuer($this->issuer)) {
            $this->logger?->error("Issuer '{$jws->getPayload()->iss}' does not match '$this->issuer'");
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

    /**
     * @throws UnexpectedValueException If EVE SSO metadata could not be fetched.
     */
    public function buildLoginUrl(string $state = ''): string
    {
        $this->setOptionsAndSsoProvider();

        return $this->sso->getAuthorizationUrl([
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
        ]);
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
     * @return AccessTokenInterface A new object if the token was refreshed
     * @throws UnexpectedValueException If EVE SSO metadata could not be fetched.
     * @throws InvalidGrantException For "invalid_grant" error, i.e. invalid or revoked refresh token.
     * @throws RuntimeException For all other errors.
     */
    public function refreshAccessToken(AccessTokenInterface $existingToken): AccessTokenInterface
    {
        $this->setOptionsAndSsoProvider();

        $newToken = null;
        if ($existingToken->getExpires() && $existingToken->hasExpired()) {
            try {
                $newToken = $this->sso->getAccessToken(
                    'refresh_token',
                    ['refresh_token' => (string)$existingToken->getRefreshToken()]
                );
            } catch (Throwable $e) {
                if ($e instanceof IdentityProviderException && $e->getMessage() === 'invalid_grant') {
                    // invalid_grant = e. g. invalid or revoked refresh token
                    throw new InvalidGrantException(previous: $e);
                } else {
                    throw new RuntimeException($e->getMessage(), previous: $e);
                }
            }
        }

        return $newToken ?? $existingToken;
    }

    /**
     * Revokes a refresh token.
     *
     * @throws UnexpectedValueException If EVE SSO metadata could not be fetched.
     * @throws UnexpectedValueException If the token could not be revoked.
     * @throws GuzzleException Any other error.
     * @see https://github.com/esi/esi-docs/blob/master/docs/sso/revoking_refresh_tokens.md
     */
    public function revokeRefreshToken(AccessTokenInterface $existingToken): void
    {
        $this->setOptionsAndSsoProvider();

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
     * @throws UnexpectedValueException
     */
    private function setOptionsAndSsoProvider(): void
    {
        if (!empty($this->options['urlMetadata'])) {
            $this->metadataUrl = (string)$this->options['urlMetadata'];
        }

        if (
            empty($this->options['urlAuthorize']) ||
            empty($this->options['urlAccessToken']) ||
            empty($this->options['urlKeySet']) ||
            empty($this->options['urlRevoke']) ||
            empty($this->options['issuer'])
        ) {

            $metadata = $this->getMetadata();

            if (empty($this->options['urlAuthorize'])) {
                $this->options['urlAuthorize'] = $metadata['authorization_endpoint'];
            }
            if (empty($this->options['urlAccessToken'])) {
                $this->options['urlAccessToken'] = $metadata['token_endpoint'];
            }
            if (empty($this->options['urlKeySet'])) {
                $this->options['urlKeySet'] = $metadata['jwks_uri'];
            }
            if (empty($this->options['urlRevoke'])) {
                $this->options['urlRevoke'] = $metadata['revocation_endpoint'];
            }
            if (empty($this->options['issuer'])) {
                $this->options['issuer'] = $metadata['issuer'];
            }
        }

        // "urlResourceOwnerDetails" is required by the GenericProvider class but not used in this package.
        $this->options['urlResourceOwnerDetails'] = '';

        // Note: This throws an InvalidArgumentException if a required option is missing, but that's
        // not the case here.
        $this->sso = new GenericProvider($this->options, ['httpClient' => $this->httpClient]);

        $this->clientId = (string)$this->options['clientId'];
        $this->clientSecret = (string)$this->options['clientSecret'];
        $this->keySetUri = (string)$this->options['urlKeySet'];
        $this->revokeUrl = (string)$this->options['urlRevoke'];
        $this->issuer = (string)$this->options['issuer'];
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
        // This is only called once if any of the options are missing.
        try {
            $response = $this->httpClient->request('GET', $this->metadataUrl);
        } catch (GuzzleException $e) {
            $this->logger?->error($e->getMessage(), ['exception' => $e]);
            throw new UnexpectedValueException('Failed to fetch metadata.', 1526220041, $e);
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

        return [
            'authorization_endpoint' => $data['authorization_endpoint'],
            'token_endpoint'         => $data['token_endpoint'],
            'jwks_uri'               => $data['jwks_uri'],
            'revocation_endpoint'    => $data['revocation_endpoint'],
            'issuer'                 => $data['issuer'],
        ];
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
        } catch (GuzzleException $e) {
            $this->logger?->error($e->getMessage(), ['exception' => $e]);
            throw new UnexpectedValueException('Failed to get public keys.', 1526220031, $e);
        }

        $keySet = json_decode($response->getBody()->getContents(), true);
        if ($keySet === null || !isset($keySet['keys']) || !is_array($keySet['keys'])) {
            throw new UnexpectedValueException('Failed to parse public keys.', 1526220032);
        }

        $this->keys = $keySet['keys'];

        return $this->keys;
    }
}
