<?php
namespace Brave\Sso\Basics;

use League\OAuth2\Client\Token\AccessTokenInterface;

class EveAuthentication implements \JsonSerializable
{
    /**
     * @var string|int
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
     * @var AccessTokenInterface
     */
    private $token;

    /**
     * @param string|int $characterId
     * @param string $characterName
     * @param string $characterOwnerHash
     * @param AccessTokenInterface $token
     * @param array $scopes
     */
    public function __construct(
        $characterId,
        $characterName,
        $characterOwnerHash,
        AccessTokenInterface $token, array $scopes = []
    ) {
        $this->characterId = $characterId;
        $this->characterName = $characterName;
        $this->characterOwnerHash = $characterOwnerHash;
        $this->token = $token;
        $this->scopes = $scopes;
    }

    /**
     * @return string|int
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
     * @return AccessTokenInterface
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
