<?php

declare(strict_types=1);

namespace Test;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class TestClient extends Client
{
    private array $responses = [];

    public function setResponse(ResponseInterface|GuzzleException ...$responses): void
    {
        $this->responses = $responses;
    }

    /**
     * @throws GuzzleException
     */
    public function send(RequestInterface $request, array $options = []): ResponseInterface
    {
        return $this->nextResponse();
    }

    /**
     * @param string $uri
     * @throws GuzzleException
     */
    public function request(string $method, $uri = '', array $options = []): ResponseInterface
    {
        return $this->nextResponse();
    }

    /**
     * @throws GuzzleException
     */
    private function nextResponse(): ResponseInterface
    {
        $next = array_shift($this->responses);
        if ($next instanceof GuzzleException) {
            throw $next;
        } else {
            return $next;
        }
    }
}
