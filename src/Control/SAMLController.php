<?php

namespace SilverStripe\SAML\Control;

use Exception;
use OneLogin_Saml2_Auth;
use OneLogin_Saml2_Error;
use OneLogin_Saml2_Utils;
use Psr\Log\LoggerInterface;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\SAML\Authenticators\SAMLAuthenticator;
use SilverStripe\SAML\Authenticators\SAMLLoginForm;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use function uniqid;

/**
 * Class SAMLController
 *
 * This controller handles serving metadata requests for the identity provider (IdP), as well as handling the creation
 * of new users and logging them into SilverStripe after being authenticated at the IdP.
 */
class SAMLController extends Controller
{
    /**
     * @var array
     */
    private static $allowed_actions = [
        'index',
        'acs',
        'metadata'
    ];

    public function index()
    {
        return $this->redirect('/');
    }

    /**
     * Assertion Consumer Service
     *
     * The user gets sent back here after authenticating with the IdP, off-site.
     * The earlier redirection to the IdP can be found in the SAMLAuthenticator::authenticate.
     *
     * After this handler completes, we end up with a rudimentary Member record (which will be created on-the-fly
     * if not existent), with the user already logged in. Login triggers memberLoggedIn hooks, which allows
     * LDAP side of this module to finish off loading Member data.
     *
     * @throws OneLogin_Saml2_Error
     * @throws \Psr\Container\NotFoundExceptionInterface
     */
    public function acs()
    {
        /** @var \OneLogin_Saml2_Auth $auth */
        $auth = Injector::inst()->get(SAMLHelper::class)->getSAMLAuth();
        $caughtException = null;

        // Force php-saml module to use the current absolute base URL (e.g. https://www.example.com/saml). This avoids
        // errors that we otherwise get when having a multi-directory ACS URL like /saml/acs).
        // See https://github.com/onelogin/php-saml/issues/249
        OneLogin_Saml2_Utils::setBaseURL(Controller::join_links($auth->getSettings()->getSPData()['entityId'], 'saml'));

        // Attempt to process the SAML response. If there are errors during this, log them and redirect to the generic
        // error page. Note: This does not necessarily include all SAML errors (e.g. we still need to confirm if the
        // user is authenticated after this block
        try {
            $auth->processResponse();
            $error = $auth->getLastErrorReason();
        } catch(Exception $e) {
            $caughtException = $e;
        }

        // If there was an issue with the SAML response, if it was missing or if the SAML response indicates that they
        // aren't authorised, then log the issue and provide a traceable error back to the user via the LoginForm
        if ($caughtException || !empty($error) || !$auth->isAuthenticated()) {
            // Log both errors (reported by php-saml and thrown as exception) with a common ID for later tracking
            $id = uniqid('SAML-');

            if ($caughtException instanceof Exception) {
                $this->getLogger()->error(sprintf(
                    '[%s] [code: %s] %s (%s:%s)',
                    $id,
                    $e->getCode(),
                    $e->getMessage(),
                    $e->getFile(),
                    $e->getLine()
                ));
            }

            if (!empty($error)) {
                $this->getLogger()->error(sprintf('[%s] %s', $id, $error));
            }

            $this->getForm()->sessionMessage(
                _t(
                    'SilverStripe\\SAML\\Control\\SAMLController.ERR_SAML_ACS_FAILURE',
                    'Unfortunately we couldn\'t log you in. If this continues, please contact your I.T. department with the following reference: {ref}',
                    ['ref' => $id]
                ),
                ValidationResult::TYPE_ERROR
            );

            // Redirect the user back to the login form to display the generic error message and reference
            $this->getRequest()->getSession()->save($this->getRequest());
            return $this->redirect('Security/login');
        }

        // If processing reaches here, then the user is authenticated - the rest of this method is just processing their
        // legitimate information and configuring their account.

        // Check that the NameID is a binary string (which signals that it is a guid
        $decodedNameId = base64_decode($auth->getNameId());
        if (ctype_print($decodedNameId)) {
            $this->getForm()->sessionMessage('NameID from IdP is not a binary GUID.', ValidationResult::TYPE_ERROR);
            $this->getRequest()->getSession()->save($this->getRequest());
            return $this->getRedirect();
        }

        // transform the NameId to guid
        $helper = SAMLHelper::singleton();
        $guid = $helper->binToStrGuid($decodedNameId);
        if (!$helper->validGuid($guid)) {
            $errorMessage = "Not a valid GUID '{$guid}' recieved from server.";
            $this->getLogger()->error($errorMessage);
            $this->getForm()->sessionMessage($errorMessage, ValidationResult::TYPE_ERROR);
            $this->getRequest()->getSession()->save($this->getRequest());
            return $this->getRedirect();
        }

        // Write a rudimentary member with basic fields on every login, so that we at least have something
        // if LDAP synchronisation fails.
        $member = Member::get()->filter('GUID', $guid)->limit(1)->first();
        if (!($member && $member->exists())) {
            $member = new Member();
            $member->GUID = $guid;
        }

        $attributes = $auth->getAttributes();

        foreach ($member->config()->claims_field_mappings as $claim => $field) {
            if (!isset($attributes[$claim][0])) {
                $this->getLogger()->warning(
                    sprintf(
                        'Claim rule \'%s\' configured in LDAPMember.claims_field_mappings, ' .
                                'but wasn\'t passed through. Please check IdP claim rules.',
                        $claim
                    )
                );

                continue;
            }

            $member->$field = $attributes[$claim][0];
        }

        $member->SAMLSessionIndex = $auth->getSessionIndex();

        // This will trigger LDAP update through LDAPMemberExtension::memberLoggedIn. The LDAP update will also write
        // the Member record a second time, but the member must be written before IdentityStore->logIn() is called.
        // Both SAML and LDAP identify Members by the GUID field.
        $member->write();

        /** @var IdentityStore $identityStore */
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $persistent = Security::config()->get('autologin_enabled');
        $identityStore->logIn($member, $persistent, $this->getRequest());

        return $this->getRedirect();
    }

    /**
     * Generate this SP's metadata. This is needed for intialising the SP-IdP relationship.
     * IdP is instructed to call us back here to establish the relationship. IdP may also be configured
     * to hit this endpoint periodically during normal operation, to check the SP availability.
     */
    public function metadata()
    {
        try {
            /** @var OneLogin_Saml2_Auth $auth */
            $auth = Injector::inst()->get(SAMLHelper::class)->getSAMLAuth();
            $settings = $auth->getSettings();
            $metadata = $settings->getSPMetadata();
            $errors = $settings->validateMetadata($metadata);
            if (empty($errors)) {
                header('Content-Type: text/xml');
                echo $metadata;
            } else {
                throw new \OneLogin_Saml2_Error(
                    'Invalid SP metadata: ' . implode(', ', $errors),
                    \OneLogin_Saml2_Error::METADATA_SP_INVALID
                );
            }
        } catch (Exception $e) {
            $this->getLogger()->error($e->getMessage());
            echo $e->getMessage();
        }
    }

    /**
     * @return HTTPResponse
     */
    protected function getRedirect()
    {
        // Absolute redirection URLs may cause spoofing
        if ($this->getRequest()->getSession()->get('BackURL')
            && Director::is_site_url($this->getRequest()->getSession()->get('BackURL'))) {
            return $this->redirect($this->getRequest()->getSession()->get('BackURL'));
        }

        // Spoofing attack, redirect to homepage instead of spoofing url
        if ($this->getRequest()->getSession()->get('BackURL')
            && !Director::is_site_url($this->getRequest()->getSession()->get('BackURL'))) {
            return $this->redirect(Director::absoluteBaseURL());
        }

        // If a default login dest has been set, redirect to that.
        if (Security::config()->default_login_dest) {
            return $this->redirect(Director::absoluteBaseURL() . Security::config()->default_login_dest);
        }

        // fallback to redirect back to home page
        return $this->redirect(Director::absoluteBaseURL());
    }

    /**
     * Get a logger
     *
     * @return LoggerInterface
     */
    public function getLogger()
    {
        return Injector::inst()->get(LoggerInterface::class);
    }

    /**
     * Gets the login form
     *
     * @return SAMLLoginForm
     */
    public function getForm()
    {
        return Injector::inst()->get(SAMLLoginForm::class, true, [$this, SAMLAuthenticator::class, 'LoginForm']);
    }
}
