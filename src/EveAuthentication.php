<?php
namespace Brave\Sso\Basics;

use League\OAuth2\Client\Token\AccessToken;

class EveAuthentication {
    /**
     * @var string
     */
    private $characterId;

    /**
     * @var string
     */
    private $characterName;

    /**
     * @var string
     */
    private $characterOwnerHash;

    /**
     * @var array
     */
    private $scopes;

    /**
     * @var AccessToken
     */
    private $token;

    /**
     * @param string $characterId
     * @param string $characterName
     * @param string $characterOwnerHash
     * @param AccessToken $token
     * @param array $scopes
     */
    public function __construct($characterId, $characterName, $characterOwnerHash, AccessToken $token, array $scopes = [])
    {
        $this->characterId = $characterId;
        $this->characterName = $characterName;
        $this->characterOwnerHash = $characterOwnerHash;
        $this->token = $token;
        $this->scopes = $scopes;
    }

    /**
     * @return string
     */
    public function getCharacterId()
    {
        return $this->characterId;
    }

    /**
     * @return string
     */
    public function getCharacterName()
    {
        return $this->characterName;
    }

    /**
     * @return string
     */
    public function getCharacterOwnerHash()
    {
        return $this->characterOwnerHash;
    }

    /**
     * @return AccessToken
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @return array
     */
    public function getScopes()
    {
        return $this->scopes;
    }
}
