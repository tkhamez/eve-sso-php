<?php
namespace Brave\Sso\Basics;

use League\OAuth2\Client\Token\ResourceOwnerAccessTokenInterface;

class EveAuthentication implements \JsonSerializable
{
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
     * @var ResourceOwnerAccessTokenInterface
     */
    private $token;

    /**
     * @param string $characterId
     * @param string $characterName
     * @param string $characterOwnerHash
     * @param ResourceOwnerAccessTokenInterface $token
     * @param array $scopes
     */
    public function __construct($characterId, $characterName, $characterOwnerHash, ResourceOwnerAccessTokenInterface $token, array $scopes = [])
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
     * @return ResourceOwnerAccessTokenInterface
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

    /**
     * Contains core data for serialisation
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return [
            'characterId' => $this->characterId,
            'character_name' => $this->characterName,
            'token' => $this->token
        ];
    }
}
