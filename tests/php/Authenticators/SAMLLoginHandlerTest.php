<?php

namespace SilverStripe\SAML\Tests\Authenticators;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\Form;
use SilverStripe\SAML\Authenticators\SAMLAuthenticator;
use SilverStripe\SAML\Authenticators\SAMLLoginForm;
use SilverStripe\SAML\Authenticators\SAMLLoginHandler;
use SilverStripe\SAML\Helpers\SAMLHelper;

/**
 * This mostly tests core functionality so is a bit redundant/silly.
 * But it ensures an interface defined by convention rather than code is followed.
 */
class SAMLLoginHandlerTest extends SapphireTest
{
    public function testLoggingIn()
    {
        $backUrl = '/samltest/acs';
        $helper = $this->createStub(SAMLHelper::class);
        $authenticator = $this->createStub(SAMLAuthenticator::class);
        $form = $this->createStub(SAMLLoginForm::class);
        $request = $this->createStub(HTTPRequest::class);

        $handler = new SAMLLoginHandler('test', $authenticator);
        $handler->setHelper($helper);
        $helper->expects($this->once())->method('redirect')->with($handler, $request, $backUrl);
        $handler->doLogin(['BackURL' => $backUrl], $form, $request);
    }

    public function testLink()
    {
        $authenticator = $this->createStub(SAMLAuthenticator::class);
        $handler = new SAMLLoginHandler('samltest', $authenticator);
        $this->assertSame('samltest', $handler->Link());
        $this->assertSame('samltest/action', $handler->Link('action'));
    }

    public function testDefaultTemplateOutput()
    {
        $authenticator = $this->createStub(SAMLAuthenticator::class);
        $handler = new SAMLLoginHandler('test', $authenticator);
        $loginAction = $handler->login();
        $this->assertTrue(is_array($loginAction));
        $this->assertArrayHasKey('Form', $loginAction);
        $this->assertInstanceOf(Form::class, $loginAction['Form']);
        $this->assertSame('test/LoginForm', $loginAction['Form']->FormAction());
        $indexAction = $handler::config()->get('url_handlers');
        $this->assertArrayHasKey('', $indexAction);
        $this->assertSame('login', $indexAction['']);
    }

    public function testLoginFormAction()
    {
        $authenticator = $this->createStub(SAMLAuthenticator::class);
        $handler = new SAMLLoginHandler('test', $authenticator);
        $loginForm = $handler->LoginForm();
        $this->assertInstanceOf(SAMLLoginForm::class, $loginForm);
        $this->assertSame('test/LoginForm', $loginForm->FormAction());
        $this->assertContains('LoginForm', $handler::config()->get('allowed_actions'));
    }
}
