<?php

declare(strict_types=1);

namespace Test;

use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Monolog\LogRecord;

class TestLogger extends Logger
{
    public function __construct()
    {
        parent::__construct('Test', [new TestHandler()]);
    }

    public function getMessages(): array
    {
        $handler = parent::getHandlers()[0];
        if ($handler instanceof TestHandler) {
            return array_map(function (LogRecord $item) {
                return $item['message'];
            }, $handler->getRecords());
        }
        return [];
    }
}
