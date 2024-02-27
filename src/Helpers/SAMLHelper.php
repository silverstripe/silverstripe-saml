<?php

namespace SilverStripe\SAML\Helpers;

use Exception;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\SAML\Authenticators\SAMLLoginHandler;
use SilverStripe\SAML\Control\SAMLController;
use SilverStripe\SAML\Services\SAMLConfiguration;
use OneLogin\Saml2\Auth;

/**
 * Class SAMLHelper
 *
 * SAMLHelper acts as a simple wrapper for the OneLogin implementation, so that we can configure
 * and inject it via the config system.
 */
class SAMLHelper
{
    use Injectable;

    /**
     * @var array
     */
    private static $dependencies = [
        'SAMLConfService' => '%$' . SAMLConfiguration::class,
    ];

    /**
     * @var SAMLConfiguration
     */
    public $SAMLConfService;

    /**
     * @return Auth
     */
    public function getSAMLauth()
    {
        $samlConfig = $this->SAMLConfService->asArray();
        return new Auth($samlConfig);
    }

    /**
     * Create a SAML AuthN request and send the user off to the identity provider (IdP) to get authenticated. This
     * method does not check to see if the user is already authenticated, that is the responsibility of the caller.
     *
     * Note: This method will *never* return via normal control flow - instead one of two things will happen:
     * - The user will be forcefully & immediately redirected to the IdP to get authenticated, OR
     * - A HTTPResponse_Exception is thrown because php-saml encountered an error while generating a valid AuthN request
     *
     * @param RequestHandler $requestHandler In case of error, we require a RequestHandler to throw errors from
     * @param HTTPRequest $request The currently active request (used to retrieve session)
     * @param string|null $backURL The URL to return to after successful SAML authentication (@see SAMLController)
     * @throws HTTPResponse_Exception
     * @see SAMLLoginHandler::doLogin() How the SAML login form handles this
     * @see SAMLController::acs() How the response is processed after the user is returned from the IdP
     * @return void This function will never return via normal control flow (see above).
     */
    public function redirect(RequestHandler $requestHandler = null, HTTPRequest $request = null, $backURL = null)
    {
        // $data is not used - the form is just one button, with no fields.
        $auth = $this->getSAMLAuth();

        if ($request) {
            $request->getSession()->set('BackURL', $backURL);
            $request->getSession()->save($request);
        }

        $additionalGetQueryParams = $this->getAdditionalGETQueryParameters();

        try {
            /** Use RelayState to convey BackURL (will be handled in {@see SAMLController}). */
            $auth->login($backURL, $additionalGetQueryParams);
        } catch (Exception $e) {
            /** @var LoggerInterface $logger */
            $logger = Injector::inst()->get(LoggerInterface::class);
            $logger->error(sprintf('[code:%s] Error during SAMLHelper->redirect: %s', $e->getCode(), $e->getMessage()));

            if ($requestHandler) {
                $requestHandler->httpError(400);
            } else {
                throw new HTTPResponse_Exception(null, 400);
            }
        }
    }

    /**
     * Checks if the string is a valid guid in the format of A98C5A1E-A742-4808-96FA-6F409E799937
     * Case in-sensitive
     *
     * @param  string $guid
     * @return bool
     */
    public function validGuid($guid)
    {
        if (preg_match('/^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}?$/i', $guid)) {
            return true;
        }
        return false;
    }

    /**
     * @param  string $object_guid
     * @return string
     */
    public function binToStrGuid($object_guid)
    {
        $hex_guid = bin2hex($object_guid);
        $hex_guid_to_guid_str = '';
        for ($k = 1; $k <= 4; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 8 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-';
        for ($k = 1; $k <= 2; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 12 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-';
        for ($k = 1; $k <= 2; ++$k) {
            $hex_guid_to_guid_str .= substr($hex_guid, 16 - 2 * $k, 2);
        }
        $hex_guid_to_guid_str .= '-' . substr($hex_guid, 16, 4);
        $hex_guid_to_guid_str .= '-' . substr($hex_guid, 20, 12);
        return strtoupper($hex_guid_to_guid_str);
    }

    /**
     * @return string[]
     */
    private function getAdditionalGETQueryParameters()
    {
        $additionalGetQueryParams = $this->SAMLConfService->config()->get('additional_get_query_params');
        if (!is_array($additionalGetQueryParams)) {
            $additionalGetQueryParams = [];
        }

        return $additionalGetQueryParams;
    }
}
