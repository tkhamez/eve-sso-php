<?php
namespace Brave\Sso\Basics;

use GuzzleHttp\Client;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class TestClient extends Client
{
    /**
     * @var ResponseInterface[]
     */
    private $responses = [];

    public function setResponse(ResponseInterface ...$responses)
    {
        $this->responses = $responses;
    }

    public function send(RequestInterface $request, array $options = [])
    {
        return array_shift($this->responses);
    }

    public function request($method, $uri = '', array $options = [])
    {
        return array_shift($this->responses);
    }
}
