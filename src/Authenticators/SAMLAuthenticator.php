<?php

namespace SilverStripe\SAML\Authenticators;

use SilverStripe\Control\Controller;
use Silverstripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\Form;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\SAML\Control\SAMLController;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\SAML\Middleware\SAMLMiddleware;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\MemberAuthenticator\MemberAuthenticator;

/**
 * Class SAMLAuthenticator
 *
 * Authenticates the user against a SAML IdP via a single sign-on process.
 * It will create a {@link Member} stub record with rudimentary fields (see {@link SAMLController::acs()})
 * if the Member record was not found.
 *
 * You can either use:
 * - just SAMLAuthenticator (which will trigger LDAP sync anyway, via LDAPMemberExtension::memberLoggedIn)
 * - just LDAPAuthenticator (syncs explicitly, but no single sign-on via IdP done)
 * - both, so people have multiple tabbed options in the login form.
 *
 * Both authenticators understand and collaborate through the GUID field on the Member.
 */
class SAMLAuthenticator extends MemberAuthenticator
{
    /**
     * @var string
     */
    private $name = 'SAML';

    /**
     * @return string
     */
    public static function get_name()
    {
        return Config::inst()->get(self::class, 'name');
    }

    /**
     * @param Controller $controller
     * @return SAMLLoginForm
     */
    public static function get_login_form(Controller $controller)
    {
        return new SAMLLoginForm($controller, 'LoginForm');
    }

    /**
     * This method does nothing, as all authentication via SAML is handled via HTTP redirects (similar to OAuth) which
     * are not supported by the Authenticator system. Authentication via SAML is only triggered when a user hits the
     * SAMLController->acs() endpoint when returning from the identity provider.
     *
     * Instead of calling this method, you should use the SAMLLoginForm, or protect your entire site by enabling the
     * SAMLMiddleware.
     *
     * @param array $data
     * @param HTTPRequest $request
     * @param ValidationResult|null $result
     * @return bool|Member|void
     * @see SAMLLoginForm
     * @see SAMLMiddleware
     */
    public function authenticate(array $data, HTTPRequest $request, ValidationResult &$result = null)
    {
        return null;
    }

    /**
     * @inheritdoc
     */
    public function getLoginHandler($link)
    {
        return SAMLLoginHandler::create($link, $this);
    }

    /**
     * @inheritdoc
     */
    public function supportedServices()
    {
        return Authenticator::LOGIN | Authenticator::LOGOUT;
    }
}
