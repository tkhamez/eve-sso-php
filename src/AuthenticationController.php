<?php
namespace Brave\Sso\Basics;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Container\ContainerInterface;

/**
 * Example authentication controller
 */
class AuthenticationController
{
    /**
     * ContainerInterface
     *
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @var string
     */
    protected $template = __DIR__ . '/../html/sso_page.html';

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    /**
     * Show the login page.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     */
    public function index(ServerRequestInterface $request, ResponseInterface $response)
    {
        $serviceName = isset($this->container->get('settings')['brave.serviceName']) ?
            $this->container->get('settings')['brave.serviceName'] : 'Brave Service';
        $authenticationProvider = $this->container->get(AuthenticationProvider::class);
        $state = $authenticationProvider->generateState();
        $sessionHandler = $this->container->get(SessionHandlerInterface::class);
        $sessionHandler->set('ssoState', $state);

        $loginUrl = $authenticationProvider->buildLoginUrl($state);

        $templateCode = file_get_contents($this->template);

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
     * @param bool $ssoV2
     * @throws \Exception
     * @return ResponseInterface
     */
    public function auth(ServerRequestInterface $request, ResponseInterface $response, $ssoV2 = false)
    {
        $queryParameters = $request->getQueryParams();

        if (!isset($queryParameters['code']) || !isset($queryParameters['state'])) {
            throw new \Exception('Invalid SSO state, please try again.');
        }

        $code = $queryParameters['code'];
        $state = $queryParameters['state'];

        /* @var $authenticationProvider AuthenticationProvider */
        $authenticationProvider = $this->container->get(AuthenticationProvider::class);
        $sessionHandler = $this->container->get(SessionHandlerInterface::class);
        $sessionState = $sessionHandler->get('ssoState');
        if ($ssoV2) {
            $eveAuthentication = $authenticationProvider->validateAuthenticationV2($state, $sessionState, $code);
        } else {
            $eveAuthentication = $authenticationProvider->validateAuthentication($state, $sessionState, $code);
        }

        $sessionHandler->set('eveAuth', $eveAuthentication);

        return $response;
    }
}
