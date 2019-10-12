<?php

declare(strict_types=1);

namespace Test;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class TestClient extends Client
{
    /**
     * @var ResponseInterface[]
     */
    private $responses = [];

    /**
     * @param ResponseInterface|GuzzleException ...$responses
     */
    public function setResponse(...$responses)
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
     * @param string $method
     * @param string $uri
     * @param array $options
     * @return ResponseInterface
     * @throws GuzzleException
     */
    public function request($method, $uri = '', array $options = []): ResponseInterface
    {
        return $this->nextResponse();
    }

    /**
     * @throws GuzzleException
     */
    private function nextResponse()
    {
        $next = array_shift($this->responses);
        if ($next instanceof GuzzleException) {
            throw $next;
        } else {
            return $next;
        }
    }
}
