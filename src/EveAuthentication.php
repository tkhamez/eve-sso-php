<?php

declare(strict_types=1);

namespace Eve\Sso;

use JsonSerializable;
use League\OAuth2\Client\Token\AccessTokenInterface;

class EveAuthentication implements JsonSerializable
{
    /**
     * @param string[] $scopes
     */
    public function __construct(
        private readonly int                  $characterId,
        private readonly string               $characterName,
        private readonly string               $characterOwnerHash,
        private readonly AccessTokenInterface $token,
        private readonly array                $scopes = []
    ) {
    }

    public function getCharacterId(): int
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

    /**
     * @return string[]
     */
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
            'characterName' => $this->characterName,
            'token' => $this->token
        ];
    }
}
