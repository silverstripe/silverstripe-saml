<?php

namespace SilverStripe\SAML\Tests\Extensions;

use ReflectionClass;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\SAML\Extensions\ErrorPageStaticPublish;
use SilverStripe\SAML\Middleware\SAMLMiddleware;

class ErrorPageStaticPublishTest extends SapphireTest
{
    public function testMiddlewareDisablesAndReenablesUsingHooksInExtension()
    {
        $config = SAMLMiddleware::config();
        $config->set('enabled', true);
        $instance = new SAMLMiddleware();
        $reflection = new ReflectionClass(SAMLMiddleware::class);
        $isEnabled = $reflection->getMethod('isEnabled');

        $errorPublish = new ErrorPageStaticPublish();

        $this->assertTrue($isEnabled->invoke($instance));

        $errorPublish->onBeforeStaticWrite();

        $this->assertFalse($isEnabled->invoke($instance));

        $errorPublish->onAfterStaticWrite();

        $this->assertTrue($isEnabled->invoke($instance));
    }
}
