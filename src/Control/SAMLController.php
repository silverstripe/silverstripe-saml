<?php

namespace SilverStripe\SAML\Control;

use Exception;

use function gmmktime;
use function uniqid;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\Utils;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\SAML\Authenticators\SAMLAuthenticator;
use SilverStripe\SAML\Authenticators\SAMLLoginForm;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\SAML\Helpers\SAMLUserGroupMapper;
use SilverStripe\SAML\Model\SAMLResponse;
use SilverStripe\SAML\Services\SAMLConfiguration;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

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
     * @throws Error
     * @throws \Psr\Container\NotFoundExceptionInterface
     */
    public function acs()
    {
        /** @var Auth $auth */
        $auth = Injector::inst()->get(SAMLHelper::class)->getSAMLAuth();
        $caughtException = null;

        // Log both errors (reported by php-saml and thrown as exception) with a common ID for later tracking
        $uniqueErrorId = uniqid('SAML-');

        // Force php-saml module to use the current absolute base URL (e.g. https://www.example.com/saml). This avoids
        // errors that we otherwise get when having a multi-directory ACS URL like /saml/acs).
        // See https://github.com/onelogin/php-saml/issues/249
        Utils::setBaseURL(Controller::join_links($auth->getSettings()->getSPData()['entityId'], 'saml'));

        // Attempt to process the SAML response. If there are errors during this, log them and redirect to the generic
        // error page. Note: This does not necessarily include all SAML errors (e.g. we still need to confirm if the
        // user is authenticated after this block
        try {
            $auth->processResponse();
            $error = $auth->getLastErrorReason();
        } catch (Exception $e) {
            $caughtException = $e;
        }

        // If there was an issue with the SAML response, if it was missing or if the SAML response indicates that they
        // aren't authorised, then log the issue and provide a traceable error back to the user via the login form
        $hasError = $caughtException || !empty($error);
        if ($hasError || !$auth->isAuthenticated() || $this->checkForReplayAttack($auth, $uniqueErrorId)) {
            if ($caughtException instanceof Exception) {
                $this->getLogger()->error(sprintf(
                    '[%s] [code: %s] %s (%s:%s)',
                    $uniqueErrorId,
                    $e->getCode(),
                    $e->getMessage(),
                    $e->getFile(),
                    $e->getLine()
                ));
            }

            if (!empty($error)) {
                $this->getLogger()->error(sprintf('[%s] %s', $uniqueErrorId, $error));
            }

            $this->getForm()->sessionMessage(
                _t(
                    'SilverStripe\\SAML\\Control\\SAMLController.ERR_SAML_ACS_FAILURE',
                    'Unfortunately we couldn\'t log you in. If this continues, please contact your I.T. department'
                        . ' with the following reference: {ref}',
                    ['ref' => $uniqueErrorId]
                ),
                ValidationResult::TYPE_ERROR
            );

            // Redirect the user back to the login form to display the generic error message and reference
            $this->getRequest()->getSession()->save($this->getRequest());
            return $this->redirect('Security/login');
        }

        /**
         * If processing reaches here, then the user is authenticated - the rest of this method is just processing their
         * legitimate information and configuring their account.
         */

        $helper = SAMLHelper::singleton();

        // If we expect the NameID to be a binary version of the GUID (ADFS), check that it actually is
        // If we are configured not to expect a binary NameID, then we assume it is a direct GUID (Azure AD)
        if (Config::inst()->get(SAMLConfiguration::class, 'expect_binary_nameid')) {
            $decodedNameId = base64_decode($auth->getNameId());
            if (ctype_print($decodedNameId)) {
                $this->getForm()->sessionMessage('NameID from IdP is not a binary GUID.', ValidationResult::TYPE_ERROR);
                $this->getRequest()->getSession()->save($this->getRequest());
                return $this->getRedirect();
            }

            // transform the NameId to guid
            $guid = $helper->binToStrGuid($decodedNameId);
            $validateGuid = true;
        } else {
            $guid = $auth->getNameId();
            // If you do not expect your NameId to be formatted as a valid GUID, then you can update this config to
            // false
            $validateGuid = Config::inst()->get(SAMLConfiguration::class, 'validate_nameid_as_guid');
        }

        if ($validateGuid && !$helper->validGuid($guid)) {
            $errorMessage = "Not a valid GUID '{$guid}' received from server.";
            $this->getLogger()->error($errorMessage);
            $this->getForm()->sessionMessage($errorMessage, ValidationResult::TYPE_ERROR);
            $this->getRequest()->getSession()->save($this->getRequest());
            return $this->getRedirect();
        }

        $this->extend('updateGuid', $guid);

        $attributes = $auth->getAttributes();

        // Allows setups that map GUID (email format) to email {@see SAMLConfiguration::$expose_guid_as_attribute}.
        if (Config::inst()->get(SAMLConfiguration::class, 'expose_guid_as_attribute')) {
            $attributes['GUID'][0] = $guid;
        }

        $fieldToClaimMap = array_flip(Member::config()->claims_field_mappings);

        // Write a rudimentary member with basic fields on every login, so that we at least have something
        // if there is no further sync (e.g. via LDAP)
        $member = Member::get()->filter('GUID', $guid)->limit(1)->first();
        $insecure = Config::inst()->get(SAMLConfiguration::class, 'allow_insecure_email_linking');

        if (!($member && $member->exists()) && $insecure && isset($fieldToClaimMap['Email'])) {
            // If there is no member found via GUID and we allow linking via email, search by email
            $att = $attributes[$fieldToClaimMap['Email']];
            $member = Member::get()->filter('Email', $att)->limit(1)->first();

            if (!($member && $member->exists())) {
                $member = new Member();
            }

            $member->GUID = $guid;
        } elseif (!($member && $member->exists())) {
            // If the member doesn't exist and we don't allow linking via email, then create a new member
            $member = new Member();
            $member->GUID = $guid;
        }

        foreach ($member->config()->claims_field_mappings as $claim => $field) {
            if (!isset($attributes[$claim][0])) {
                $this->getLogger()->warning(
                    sprintf(
                        'Claim rule \'%s\' configured in SAMLMemberExtension.claims_field_mappings, ' .
                            'but wasn\'t passed through. Please check IdP claim rules.',
                        $claim
                    )
                );

                continue;
            }

            $member->$field = $attributes[$claim][0];
        }

        $member->SAMLSessionIndex = $auth->getSessionIndex();

        // This will trigger LDAP update through LDAPMemberExtension::memberLoggedIn, if the LDAP module is installed.
        // The LDAP update will also write the Member record a second time, but the member *must* be written before
        // IdentityStore->logIn() is called, otherwise the identity store throws an exception.
        // Both SAML and LDAP identify Members by the same GUID field.
        $member->write();

        $mapUserGroup = Config::inst()->get(SAMLConfiguration::class, 'map_user_group');
        // Map user groups
        if ($mapUserGroup) {
            $mapper = SAMLUserGroupMapper::singleton();

            $member = $mapper->map($attributes, $member);
        }

        // Hook for modifying login behaviour
        $this->extend('updateLogin');

        /** @var IdentityStore $identityStore */
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $identityStore->logIn($member, false, $this->getRequest());

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
            /** @var Auth $auth */
            $auth = Injector::inst()->get(SAMLHelper::class)->getSAMLAuth();
            $settings = $auth->getSettings();
            $metadata = $settings->getSPMetadata();
            $errors = $settings->validateMetadata($metadata);
            if (empty($errors)) {
                header('Content-Type: text/xml');
                echo $metadata;
            } else {
                throw new Error(
                    'Invalid SP metadata: ' . implode(', ', $errors),
                    Error::METADATA_SP_INVALID
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
        $back = $this->getRequest()->getSession()->get('BackURL');

        if ($back && Director::is_site_url($back)) {
            return $this->redirect($this->getRequest()->getSession()->get('BackURL'));
        }

        // Spoofing attack, redirect to homepage instead of spoofing url
        if ($back && !Director::is_site_url($back)) {
            return $this->redirect(Director::absoluteBaseURL());
        }

        // If a default login dest has been set, redirect to that.
        if ($dest = Security::config()->default_login_dest) {
            return $this->redirect(Director::absoluteBaseURL() . $dest);
        }

        // fallback to redirect back to home page
        return $this->redirect(Director::absoluteBaseURL());
    }

    /**
     * If processing reaches here, then the user is authenticated but potentially not valid. We first need to confirm
     * that they are not an attacker performing a SAML replay attack (capturing the raw traffic from a compromised
     * device and then re-submitting the same SAML response).
     *
     * To combat this, we store SAML response IDs for the amount of time they're valid for (plus a configurable offset
     * to account for potential time skew), and if the ID has been seen before we log an error message and return true
     * (which indicates that this specific request is a replay attack).
     *
     * If no replay attack is detected, then the SAML response is logged so that future requests can be blocked.
     *
     * @param Auth $auth The Auth object that includes the processed response
     * @param string $uniqueErrorId The error code to use when logging error messages for this given error
     * @return bool true if this response is a replay attack, false if it's the first time we've seen the ID
     */
    protected function checkForReplayAttack(Auth $auth, $uniqueErrorId = '')
    {
        $responseId = $auth->getLastMessageId();
        $expiry = $auth->getLastAssertionNotOnOrAfter(); // Note: Expiry will always be stored and returned in UTC

        // Search for any SAMLResponse objects where the response ID is the same and the expiry is within the range
        $count = SAMLResponse::get()->filter(['ResponseID' => $responseId])->count();

        if ($count > 0) {
            // Response found, therefore this is a replay attack - log the error and return false so the user is denied
            $this->getLogger()->error(sprintf(
                '[%s] SAML replay attack detected! Response ID "%s", expires "%s", client IP "%s"',
                $uniqueErrorId,
                $responseId,
                $expiry,
                $this->getRequest()->getIP()
            ));

            return true;
        } else {
            // No attack detected, log the SAML response
            $response = new SAMLResponse([
                'ResponseID' => $responseId,
                'Expiry' => $expiry
            ]);

            $response->write();
            return false;
        }
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
