<?php

declare(strict_types=1);

namespace Eve\Sso;

use Psr\Container\ContainerInterface;

interface SessionHandlerInterface
{
    public function __construct(ContainerInterface $container);

    /**
     * @param int|string $name
     * @param mixed $value
     * @return mixed
     */
    public function set($name, $value);

    /**
     * @param int|string $name
     * @param mixed|null $default
     * @return mixed|null
     */
    public function get($name, $default = null);
}
