<?php

declare(strict_types=1);

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
        string $characterName,
        string $characterOwnerHash,
        AccessTokenInterface $token,
        array $scopes = []
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

    public function getCharacterName(): string
    {
        return $this->characterName;
    }

    public function getCharacterOwnerHash(): string
    {
        return $this->characterOwnerHash;
    }

    public function getToken(): AccessTokenInterface
    {
        return $this->token;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Contains core data for serialisation
     */
    public function jsonSerialize(): array
    {
        return [
            'characterId' => $this->characterId,
            'character_name' => $this->characterName,
            'token' => $this->token
        ];
    }
}
