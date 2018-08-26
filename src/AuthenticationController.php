<?php
namespace Brave\Sso\Basics;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Container\ContainerInterface;

class AuthenticationController {
    /**
     * ContainerInterface
     *
     * @var ContainerInterface
     */
    protected $container;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    /**
     * Show the login page.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param array $arguments
     * @return ResponseInterface
     */
    public function index(ServerRequestInterface $request, ResponseInterface $response, $arguments)
    {
        $serviceName = isset($this->container->get('settings')['brave.serviceName']) ? $this->container->get('settings')['brave.serviceName'] : 'Brave Service';
        $authenticationProvider = $this->container->get(\Brave\Sso\Basics\AuthenticationProvider::class);
        $state = $authenticationProvider->generateState();
        $sessionHandler = $this->container->get(\Brave\Sso\Basics\SessionHandlerInterface::class);
        $sessionHandler->set('ssoState', $state);

        $loginUrl = $authenticationProvider->buildLoginUrl($state);

        $templateCode = file_get_contents(__DIR__ . '/../html/sso_page.html');

        $body = str_replace([
            '{{serviceName}}',
            '{{loginUrl}}'
        ], [
            $serviceName,
            $loginUrl
        ], $templateCode);

        $response->getBody()->write($body);

        return $response;
    }

    /**
     * EVE SSO callback.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param array $arguments
     * @throws \Exception
     * @return ResponseInterface
     */
    public function auth(ServerRequestInterface $request, ResponseInterface $response, $arguments)
    {
        $queryParameters = $request->getQueryParams();

        if (!isset($queryParameters['code']) || !isset($queryParameters['state'])) {
            throw new \Exception('Invalid SSO state, please try again.');
        }

        $code = $queryParameters['code'];
        $state = $queryParameters['state'];

        $authenticationProvider = $this->container->get(\Brave\Sso\Basics\AuthenticationProvider::class);
        $sessionHandler = $this->container->get(\Brave\Sso\Basics\SessionHandlerInterface::class);
        $sessionState = $sessionHandler->get('ssoState');
        $eveAuthentication = $authenticationProvider->validateAuthentication($state, $sessionState, $code);

        $sessionHandler->set('eveAuth', $eveAuthentication);

        return $response;
    }
}
