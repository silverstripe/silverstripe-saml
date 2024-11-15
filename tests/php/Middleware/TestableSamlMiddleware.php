<?php

namespace SilverStripe\SAML\Tests\Middleware;

use SilverStripe\Dev\TestOnly;
use SilverStripe\SAML\Middleware\SAMLMiddleware;

/**
 * SAMLMiddleware calls Director::is_cli() which is always true when running tests.
 * This means it is impossible to test {@see process()} due to this test always allowing the request through, instead of
 * being subject to further tests, or returning the SAML redirect.
 *
 * We use a subclass because we can then stub the superclass' method, and provide a way to affect its return value so we
 * can test both execution paths. Using PHPUnits mocking methods do not work as the method is of `protected` visibility.
 */
class TestableSamlMiddleware extends SAMLMiddleware implements TestOnly
{
    public bool $excludedEnvironment = false;

    protected function isExcludedEnvironment(): bool
    {
        return $this->excludedEnvironment;
    }
}
