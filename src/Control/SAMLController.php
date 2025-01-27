<?php

namespace SilverStripe\SAML\Control;

use Exception;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\Utils;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Config_ForClass;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\Filters\ExactMatchFilter;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\SAML\Authenticators\SAMLAuthenticator;
use SilverStripe\SAML\Authenticators\SAMLLoginForm;
use SilverStripe\SAML\Exceptions\AcsFailure;
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
    private static $url_segment = 'saml';

    /**
     * @var array
     */
    private static $allowed_actions = [
        'index',
        'acs',
        'metadata',
    ];

    private static $dependencies = [
        'Helper' => '%$' . SAMLHelper::class,
    ];

    private ?SAMLHelper $helper = null;

    private ?LoggerInterface $logger = null;

    private ?Config_ForClass $configuration = null;

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
        $auth = $this->getHelper()->getSAMLAuth();
        $this->configuration = SAMLConfiguration::config();

        // Log both errors (reported by php-saml and thrown as exception) with a common ID for later tracking
        $uniqueErrorId = uniqid('SAML-');

        // Force php-saml module to use the current absolute base URL (e.g. https://www.example.com/saml). This avoids
        // errors that we otherwise get when having a multi-directory ACS  URL (like /saml/acs).
        // See https://github.com/onelogin/php-saml/issues/249
        Utils::setBaseURL(Controller::join_links(Director::absoluteBaseURL(), 'saml'));

        // Hook point to allow extensions to further modify or unset any of the above base url coercion
        $this->extend('onBeforeAcs', $uniqueErrorId);

        try {
            $this->processAuthentication($auth);
            $this->checkForReplayAttack($auth);
            /**
             * If processing reaches here, then the user is authenticated - the rest of this method is just processing
             * their legitimate information and configuring their account.
             */

            $guid = $this->extractNameId($auth);
            $this->extend('updateGuid', $guid);

            $claims = $this->mapAttributes($auth, $guid, $uniqueErrorId);

            $request = $this->getRequest();
            $this->extend('updateRequest', $request);

            $member = $this->findOrCreateMember($guid, $claims['Email'] ?? null);

            if ($this->configuration->get('map_user_group')) {
                SAMLUserGroupMapper::singleton()->map($attributes, $member);
            }

            // Write a member with basic fields on every login, so that we at least have something if there is no
            // further sync (e.g. via LDAP). Silverstripe skips writes by default if there are no changes to saved
            // properties. This will trigger LDAP update through LDAPMemberExtension::memberLoggedIn, if the LDAP module
            // is installed. The LDAP update will also write the Member record a second time, but the member *must* be
            // written before IdentityStore->logIn() is called, otherwise the identity store throws an exception.
            // Both SAML and LDAP identify Members by the same GUID field.
            $member->update(['SAMLSessionIndex' => $auth->getSessionIndex(), ...$claims])->write();

            // Hook for modifying login behaviour
            $this->extend('updateLogin');
            // log user in
            Injector::inst()->get(IdentityStore::class)->logIn(
                $member,
                $this->configuration->get('login_persistent'),
                $request
            );
        } catch (AcsFailure $fail) {
            if (!empty($errorMessage = $fail->getMessage())) {
                $this->getLogger()->error("[$uniqueErrorId] $errorMessage");
            }
            $this->getForm()->sessionMessage(_t(
                self::class . '.ERR_SAML_ACS_FAILURE',
                'Unfortunately we couldn\'t log you in. If this continues, please contact your I.T. department with the'
                    . ' following reference: {ref}',
                ['ref' => $uniqueErrorId]
            ));
            // We never completed to the "logged in" state, so redirect the user back to the login form to display the
            // generic error message and reference
            return $this->redirect(Security::login_url());
        }

        return $this->getRedirect();
    }

    private function processAuthentication(Auth $auth): void
    {
        // Attempt to process the SAML response. If there are errors during this, log them and redirect to the generic
        // error page. Note: This does not necessarily include all SAML errors (e.g. we still need to confirm if the
        // user is authenticated after this block
        $error = null;
        $caughtException = null;
        try {
            $auth->processResponse();
            $error = $auth->getLastErrorReason();
        } catch (Exception $e) {
            $caughtException = $e;
            $error = sprintf('[code: %s] %s (%s:%s)', $e->getCode(), $e->getMessage(), $e->getFile(), $e->getLine());
        }

        // If there was an issue with the SAML response, if it was missing or if the SAML response indicates that they
        // aren't authorised, then log the issue and provide a traceable error back to the user via the login form
        if ($error || !$auth->isAuthenticated()) {
            throw new AcsFailure($error ?: 'Authentication failed at IdP', 0, $caughtException);
        }
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
     * @throws AcsFailure if this response is a replay attack
     */
    protected function checkForReplayAttack(Auth $auth): void
    {
        $responseId = $auth->getLastMessageId();
        $expiry = $auth->getLastAssertionNotOnOrAfter(); // Note: Expiry will always be stored and returned in UTC

        // Search for any SAMLResponse objects where the response ID is the same and the expiry is within the range
        if (SAMLResponse::get()->filter(['ResponseID' => $responseId])->count() > 0) {
            // Response found, therefore this is a replay attack - log the error and return false so the user is denied
            throw new AcsFailure(sprintf(
                'SAML replay attack detected! Response ID "%s", expires "%s", client IP "%s"',
                $responseId,
                $expiry,
                $this->getRequest()->getIP()
            ));
        }
        // No attack detected, log the SAML response
        SAMLResponse::create()->update(['ResponseID' => $responseId, 'Expiry' => $expiry])->write();
    }

    private function extractNameId(Auth $auth): string
    {
        $nameId = $auth->getNameId();
        $validateGuid = true;

        // If we expect the NameID to be a binary version of the GUID (ADFS), check that it actually is
        // If we are configured not to expect a binary NameID, then we assume it is a direct GUID (Azure AD)
        if ($this->configuration->get('expect_binary_nameid')) {
            $decodedNameId = base64_decode($nameId);
            if (ctype_print($decodedNameId)) {
                throw new AcsFailure('NameID from IdP is not a binary GUID');
            }
            // transform the NameId to guid
            $nameId = $this->getHelper()->binToStrGuid($decodedNameId);
        } else {
            // If you do not expect your NameId to be formatted as a valid GUID, then update this config to false
            $validateGuid = $this->configuration->get('validate_nameid_as_guid');
        }

        if ($validateGuid && !$this->getHelper()->validGuid($nameId)) {
            throw new AcsFailure("Invalid GUID '{$nameId}' received from IdP");
        }

        return $nameId;
    }

    private function mapAttributes(Auth $auth, string $guid, string $uniqueErrorId): array
    {
        $attributes = $auth->getAttributes();
        /** Allow for mapping GUID (email format) to email {@see SAMLConfiguration::$expose_guid_as_attribute}. */
        if ($this->configuration->get('expose_guid_as_attribute')) {
            $attributes['GUID'][0] = $guid;
        }
        $this->extend('updateAttributes', $attributes);

        $memberProperties = [];

        foreach (array_flip((array)Member::config()->get('claims_field_mappings')) as $field => $claim) {
            if (!isset($attributes[$claim][0])) {
                $this->getLogger()->warning(sprintf(
                    '[%s] Claim rule \'%s\' configured in SAMLMemberExtension.claims_field_mappings, but wasn\'t passed'
                        . ' through. Please check IdP claim rules.',
                    $uniqueErrorId,
                    $claim
                ));

                continue;
            }

            $memberProperties[$field] = $attributes[$claim][0];
        }

        return $memberProperties;
    }

    private function findOrCreateMember(string $guid, ?string $email = null): Member
    {
        $memberLookup = Member::get()->sort('GUID', 'DESC')->limit(1);
        $dataQuery = $memberLookup->dataQuery();
        $guidFieldValue = ['GUID' => $guid];
        if ($email && $this->configuration->get('allow_insecure_email_linking')) {
            // This is a long winded equivalent to the SQL fragment (Framework ORM doesn't support anything more simple)
            // ("GUID" = ? OR ("Email" = ? AND "GUID" IS NULL))
            $filterObject = $dataQuery->disjunctiveGroup();
            ExactMatchFilter::create('GUID', $guid)->apply($filterObject);
            $insecureMatch = $filterObject->conjunctiveGroup();
            foreach (['Email' => $email, 'GUID' => null] as $field => $value) {
                ExactMatchFilter::create($field, $value)->apply($insecureMatch);
            }
            $filterObject->where($insecureMatch);
            $memberLookup = $memberLookup->setDataQuery($dataQuery);
        } else {
            $memberLookup = $memberLookup->filter($guidFieldValue);
        }
        $member = $memberLookup->first() ?? Member::create();
        return $member->update($guidFieldValue);
    }

    /**
     * @return HTTPResponse
     */
    protected function getRedirect()
    {
        $request = $this->getRequest();
        $back = $request->getSession()->get('BackURL');

        // Absolute redirection URLs may cause spoofing
        if ($back && Director::is_site_url($back)) {
            return $this->redirect($back);
        }

        // In SAMLHelper, we use RelayState to convey BackURL because in a HTTP POST flow
        // with lax or strict cookie security the session will not be there for us. RelayState
        // will be reflected back in the acs POST request.
        // Note if only assertion is signed, RelayState cannot be trusted. Prevent open relay
        // as in https://github.com/SAML-Toolkits/php-saml#avoiding-open-redirect-attacks
        $relayState = $request->postVar('RelayState');
        if ($relayState && Director::is_site_url($relayState)) {
            return $this->redirect($relayState);
        }

        // Spoofing attack, redirect to homepage instead of spoofing url
        if ($back && !Director::is_site_url($back)) {
            $this->getLogger()->alert('Potential after log in redirect attack via session BackURL: ' . $back);
            return $this->redirect(Director::absoluteBaseURL());
        }

        // If a default login dest has been set, redirect to that.
        if ($dest = Security::config()->get('default_login_dest')) {
            return $this->redirect(Director::absoluteURL($dest));
        }

        // fallback to redirect back to home page
        return $this->redirect(Director::absoluteBaseURL());
    }

    /**
     * Generate this SP's metadata. This is needed for initialising the SP-IdP relationship.
     * IdP is instructed to call us back here to establish the relationship. IdP may also be configured
     * to hit this endpoint periodically during normal operation, to check the SP availability.
     *
     * @return HTTPResponse
     * @throws Error when metadata is invalid
     */
    public function metadata()
    {
        $response = $this->getResponse();
        try {
            /** @var Auth $auth */
            $auth = $this->getHelper()->getSAMLAuth();
            $settings = $auth->getSettings();
            $metadata = $settings->getSPMetadata();
            $errors = $settings->validateMetadata($metadata);
            if (empty($errors)) {
                $response->addHeader('Content-Type', 'text/xml');
                $response->setBody($metadata);
            } else {
                throw new Error('Invalid SP metadata: ' . implode(', ', $errors), Error::METADATA_SP_INVALID);
            }
        } catch (Exception $e) {
            $this->getLogger()->error($e->getMessage());
            $this->httpError(500, $e->getMessage());
        }
        return $response;
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger()
    {
        return $this->logger ??= Injector::inst()->get(LoggerInterface::class);
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Gets the login form so error messages can configured for it in order to be displayed to users
     *
     * @return SAMLLoginForm
     */
    private function getForm()
    {
        return Injector::inst()->get(SAMLAuthenticator::class)->getLoginHandler($this->Link())->loginForm();
    }

    public function getHelper(): SAMLHelper
    {
        return $this->helper ??= SAMLHelper::singleton();
    }

    public function setHelper(SAMLHelper $helper): self
    {
        $this->helper = $helper;
        return $this;
    }
}
