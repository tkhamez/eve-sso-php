<?php
namespace Brave\Sso\Basics;

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
    private $scopes;

    /**
     *
     * @param GenericProvider $sso
     * @param array $scopes
     */
    public function __construct(GenericProvider $sso, array $scopes = [])
    {
        $this->sso = $sso;
        $this->scopes = $scopes;
    }

    /**
     * @param array $scopes
     * @return $this
     */
    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;

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
        if (! is_array($verify) ||
            ! isset($verify['CharacterID']) ||
            ! isset($verify['CharacterName']) ||
            ! isset($verify['CharacterOwnerHash'])
        ) {
            throw new \UnexpectedValueException('Error obtaining Character ID.', 1526239971);
        }

        // verify scopes (user can manipulate the SSO login URL)
        $scopes = isset($verify['Scopes']) ? $verify['Scopes'] : '';
        $scopeList = explode(' ', $scopes);

        if (!$this->verifyScopes($scopeList)) {
            throw new \UnexpectedValueException('Required scopes do not match.', 1526239938);
        }

        return new EveAuthentication(
            $verify['CharacterID'],
            $verify['CharacterName'],
            $verify['CharacterOwnerHash'],
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
}
