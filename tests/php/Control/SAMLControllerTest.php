<?php

namespace SilverStripe\SAML\Tests\Control;

use Exception;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Settings;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\Form;
use SilverStripe\SAML\Control\SAMLController;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\Security\Security;

class SAMLControllerTest extends SapphireTest
{
    private const BASE = 'https://running.test';

    private function invokeMethodOnSAMLController(string $method, ?HTTPRequest $request = null): mixed
    {
        if (is_null($request)) {
            $request = $this->createStub(HTTPRequest::class);
        }
        if (!$request->hasSession()) {
            $request->method('getSession')->willReturn($this->createStub(Session::class));
        }
        $controller = new SAMLController();
        $controller->setRequest($request);
        $reflection = new \ReflectionClass(SAMLController::class);
        $method = $reflection->getMethod($method);
        return $method->invoke($controller);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Director::config()->set('alternate_base_url', self::BASE);
    }

    public function testGetFormReturnsAForm(): void
    {
        SAMLController::config()->set('url_segment', 'test');

        $form = $this->invokeMethodOnSAMLController('getForm');

        $this->assertNotNull($form);
        $this->assertInstanceOf(Form::class, $form);
        $this->assertSame('test/LoginForm', $form->FormAction());
    }

    public function testIndex()
    {
        $controller = new SAMLController();
        $response = $controller->index();
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame(self::BASE, $response->getHeader('location'));
    }

    public function testGetRedirectWithBackUrl()
    {
        $request = $this->createStub(HTTPRequest::class);
        $session = $this->createStub(Session::class);
        $request->method('getSession')->willReturn($session);
        $session->method('get')->with('BackURL')->willReturn('/some-page');
        $redirectResponse = $this->invokeMethodOnSAMLController('getRedirect', $request);
        $this->assertSame(302, $redirectResponse->getStatusCode());
        $this->assertSame(self::BASE . '/some-page', $redirectResponse->getHeader('location'));
    }

    public function testGetRedirectWithRelayState()
    {
        $request = $this->createStub(HTTPRequest::class);
        $request->method('postVar')->with('RelayState')->willReturn('/relay-state');
        $redirectResponse = $this->invokeMethodOnSAMLController('getRedirect', $request);
        $this->assertSame(302, $redirectResponse->getStatusCode());
        $this->assertSame(self::BASE . '/relay-state', $redirectResponse->getHeader('location'));
    }

    public function testGetRedirectWithBadDestination()
    {
        $request = $this->createStub(HTTPRequest::class);
        $session = $this->createStub(Session::class);
        $request->method('getSession')->willReturn($session);
        $session->method('get')->with('BackURL')->willReturn('https://examle.com/another-site');
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('alert')->with(
            'Potential after log in redirect attack via session BackURL: https://examle.com/another-site'
        );
        Injector::inst()->registerService($logger, LoggerInterface::class);
        $redirectResponse = $this->invokeMethodOnSAMLController('getRedirect', $request);
        $this->assertSame(302, $redirectResponse->getStatusCode());
        $this->assertSame(self::BASE, $redirectResponse->getHeader('location'));
    }

    public function testGetRedirectWithSecurityDefault()
    {
        $logIn = '/default/logged-in';
        Security::config()->set('default_login_dest', $logIn);
        $redirectResponse = $this->invokeMethodOnSAMLController('getRedirect');
        $this->assertSame(302, $redirectResponse->getStatusCode());
        $this->assertSame(self::BASE . $logIn, $redirectResponse->getHeader('location'));
    }

    public function testGetRedirectWithFallback()
    {
        Security::config()->set('default_login_dest', null);
        $redirectResponse = $this->invokeMethodOnSAMLController('getRedirect');
        $this->assertSame(302, $redirectResponse->getStatusCode());
        $this->assertSame(self::BASE, $redirectResponse->getHeader('location'));
    }

    public function testGoodMetadata()
    {
        $metadata = <<<XML
        <?xml version="1.0" encoding="UTF-8"?>
        <saml>
            SAML stuff
        </saml>
        XML;
        $errors = [];

        $helper = $this->createStub(SAMLHelper::class);
        $auth = $this->createStub(Auth::class);
        $settings = $this->createStub(Settings::class);
        $helper->method('getSAMLAuth')->willReturn($auth);
        $auth->method('getSettings')->willReturn($settings);
        $settings->method('getSPMetadata')->willReturn($metadata);
        $settings->method('validateMetadata')->willReturn($errors);
        Injector::inst()->registerService($helper, SAMLHelper::class);

        $controller = new SAMLController();
        $response = $controller->metadata();

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('text/xml', $response->getHeader('content-type'));
        $this->assertSame($metadata, $response->getBody());
    }

    public function testBadMetadata()
    {
        $metadata = <<<XML
        <?xml version="1.0" encoding="UTF-8"?>
        <saml>
            SAML stuff
        </saml>
        XML;
        $errors = ['something bad', 'formatting error'];
        $errorMessage = 'Invalid SP metadata: something bad, formatting error';

        $helper = $this->createStub(SAMLHelper::class);
        $auth = $this->createStub(Auth::class);
        $settings = $this->createStub(Settings::class);
        $logger = $this->createMock(LoggerInterface::class);
        $helper->method('getSAMLAuth')->willReturn($auth);
        $auth->method('getSettings')->willReturn($settings);
        $settings->method('getSPMetadata')->willReturn($metadata);
        $settings->method('validateMetadata')->willReturn($errors);
        $logger->expects($this->once())->method('error')->with($errorMessage);
        Injector::inst()->registerService($helper, SAMLHelper::class);
        Injector::inst()->registerService($logger, LoggerInterface::class);

        $controller = new SAMLController();
        $response = null;

        try {
            $exception = $controller->metadata();
        } catch (HTTPResponse_Exception $exception) {
            $response = $exception->getResponse();
        }

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeader('content-type'));
        $this->assertSame($errorMessage, $response->getBody());
    }

    public function testMetadataUnexpectedException()
    {
        $errorMessage = 'Bad things happened';

        $helper = $this->createStub(SAMLHelper::class);
        $auth = $this->createStub(Auth::class);
        $settings = $this->createStub(Settings::class);
        $logger = $this->createMock(LoggerInterface::class);
        $logger = $this->createMock(LoggerInterface::class);
        $helper->method('getSAMLAuth')->willReturn($auth);
        $auth->method('getSettings')->willReturn($settings);
        $settings->method('getSPMetadata')->willThrowException(new Exception($errorMessage));
        $logger->expects($this->once())->method('error')->with($errorMessage);
        Injector::inst()->registerService($helper, SAMLHelper::class);
        Injector::inst()->registerService($logger, LoggerInterface::class);

        $controller = new SAMLController();
        $response = null;

        try {
            $exception = $controller->metadata();
        } catch (HTTPResponse_Exception $exception) {
            $response = $exception->getResponse();
        }

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame('text/plain', $response->getHeader('content-type'));
        $this->assertSame($errorMessage, $response->getBody());
    }
}
