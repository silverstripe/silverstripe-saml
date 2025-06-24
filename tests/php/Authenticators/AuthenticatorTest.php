<?php

namespace SilverStripe\SAML\Tests\Authenticators;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\SAML\Authenticators\SAMLAuthenticator;
use SilverStripe\SAML\Authenticators\SAMLLoginHandler;
use SilverStripe\Security\Authenticator;

class AuthenticatorTest extends SapphireTest
{
    public function testAuthenticateDoesNothing()
    {
        $request = $this->createMock(HTTPRequest::class);
        $request->expects($this->never())->method($this->anything());
        $valid = $this->createMock(ValidationResult::class);
        $valid->expects($this->never())->method($this->anything());
        $data = [];
        $authenticator = new SAMLAuthenticator();
        $this->assertNull($authenticator->authenticate($data, $request, $valid));
        $this->assertEmpty($data);
    }

    public function testLoginHandlerIsCorrectType()
    {
        $authenticator = new SAMLAuthenticator();
        $this->assertInstanceOf(SAMLLoginHandler::class, $authenticator->getLoginHandler('test'));
    }

    public function testUnsupportedServices()
    {
        // These actions are the responsibility of the IdP and are never performed by Silverstripe as an SP.
        // We are less concerned whether a site supports SLO for example
        // so we're checking what shouldn't be, not what is.
        $unsupported = Authenticator::CHANGE_PASSWORD | Authenticator::CHECK_PASSWORD | Authenticator::RESET_PASSWORD;
        $everything = $unsupported | Authenticator::LOGIN | Authenticator::LOGOUT | Authenticator::CMS_LOGIN;
        $authenticator = new SAMLAuthenticator();
        $this->assertSame($unsupported, ($authenticator->supportedServices() ^ $everything) & $unsupported);
    }
}
