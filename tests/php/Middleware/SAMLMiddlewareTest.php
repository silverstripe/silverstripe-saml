<?php

namespace SilverStripe\SAML\Tests\Middleware;

use ReflectionMethod;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\SAML\Middleware\SAMLMiddleware;
use SilverStripe\Security\Security;
use stdClass;

class SAMLMiddlewareTest extends SapphireTest
{
    public function setUp(): void
    {
        parent::setUp();
        $this->logOut();
        $config = SAMLMiddleware::config();
        $config->set('excluded_urls', [
            '/^Security/i',
            '/^saml/i',
            '/^test-url\/sub-page/i'
        ]);
        $config->set('enabled', true);
    }

    public function urlChecks()
    {
        return [
            ['home', false],
            ['home/about-us', false],
            ['contact-us', false],
            ['contact-us/security', false],
            ['security', true],
            ['saml', true],
            ['saml/acs', true],
            ['test-url', false],
            ['test-url/some-page', false],
            ['test-url/some-page/sub-page', false],
            ['test-url/sub-page', true],
        ];
    }

    /**
     * @dataProvider urlChecks
     *
     * @return void
     */
    public function testIsExcludedURL($url, $expected)
    {
        $request = $this->createStub(HTTPRequest::class);
        $request->method('getUrl')->willReturn($url);
        $middleware = new SAMLMiddleware();
        $reflection = new ReflectionMethod(SAMLMiddleware::class, 'isExcludedUrl');
        $this->assertSame($expected, $reflection->invokeArgs($middleware, [$request]));
    }

    /**
     * Helper for testing the process method. Uses {@see TestableSamlMiddlware} (a subclass) in order to be able to
     * affect the value of the {@see SAMLMiddleware::isExcludedEnvironment()} so that we're not testing and asserting
     * a false-positive for success.
     *
     * @param boolean $expectedDelegation
     * @return void
     */
    private function callMiddleware(
        bool $expectDelegation = true,
        bool $excludedEnvironment = false,
        string $url = 'test/url'
    ) {
        $middleware = new TestableSamlMiddleware();
        $middleware->excludedEnvironment = $excludedEnvironment;
        $request = new HTTPRequest('GET', $url);
        $delegate = $this->getMockBuilder(stdClass::class)->addMethods(['process'])->getMock();
        $delegate->expects($expectDelegation ? $this->once() : $this->never())->method('process')->with($request);
        $helper = $this->createStub(SAMLHelper::class);
        Injector::inst()->registerService($helper, SAMLHelper::class);
        $helper->expects($expectDelegation ? $this->never() : $this->once())
            ->method('redirect')
            ->with(null, $request, $url);
        return $middleware->process($request, [$delegate, 'process']);
    }

    public function testProcessProtectsSite()
    {
        $response = $this->callMiddleware(expectDelegation: false);
    }

    public function testProcessDisabled()
    {
        SAMLMiddleware::config()->set('enabled', false);
        $this->callMiddleware();
    }

    public function testProcessExcludedURL()
    {
        $response = $this->callMiddleware(url: 'test-url/sub-page');
    }

    public function testProcessExcludedEnvironment()
    {
        $response = $this->callMiddleware(excludedEnvironment: true);
    }

    public function testProcessAlreadyAuthenticated()
    {
        Security::setCurrentUser(true); //only has to be boolean; it's not type hinted.
        $response = $this->callMiddleware();
    }
}
