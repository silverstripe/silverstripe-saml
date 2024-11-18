<?php

namespace SilverStripe\SAML\Tests\Authenticators;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Control\Session;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\SAML\Authenticators\SAMLLoginForm;
use SilverStripe\Security\Security;

class LogInFormTest extends SapphireTest
{
    private $handler = null;

    public function setUp(): void
    {
        parent::setUp();
        $handler = $this->createStub(RequestHandler::class);
        $request = $this->createStub(HTTPRequest::class);
        $handler->method('getRequest')->willReturn($request);
        $session = $this->createStub(Session::class);
        $request->method('getSession')->willReturn($session);
        $this->handler = $handler;
    }

    public function testActionIsLogInWhenUnauthenticated()
    {
        $form = new SAMLLoginForm($this->handler, 'test');
        $this->assertSame('action_doLogin', $form->Actions()->first()->getName());
    }

    public function testActionIsLogOutWhenAuthenticated()
    {
        Security::setCurrentUser('Not Null.');
        $form = new SAMLLoginForm($this->handler, 'test');
        $this->assertSame('action_logout', $form->Actions()->first()->getName());
    }

    public function testLogOutIsLocalNotSSO()
    {
        Security::setCurrentUser('Not Null.');
        $form = new SAMLLoginForm($this->handler, 'test');
        $this->assertStringStartsWith('/Security/logout', $form->FormAction());
    }

    public function testLogInFormStillHasXSSProtection()
    {
        $fields = (new SAMLLoginForm($this->handler, 'test'))->Fields();
        $this->assertCount(1, $fields);
        $this->assertSame('SecurityID', $fields->first()->getName());
    }

    public function tearDown(): void
    {
        Security::setCurrentUser(null);
        parent::tearDown();
    }
}
