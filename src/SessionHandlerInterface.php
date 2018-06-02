<?php
namespace Brave\Sso\Basics;

interface SessionHandlerInterface {

    public function __construct(\Psr\Container\ContainerInterface $container);

    public function set($name, $value);

    public function get($name, $value);
}