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
    public function getSAMLauth(): Auth
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
     * Checks if the string is a valid guid
     *
     * A GUID is 32 hexadecimal digits with hyphen separators making groups of 8, 4, 4, 4, 12.
     * E.g. A98C5A1E-A742-4808-96FA-6F409E799937
     * Check is case in-sensitive
     *
     * @param  string $guid
     * @return bool
     */
    #[PURE]
    public function validGuid(string $guid): bool
    {
        $hex = '[[:xdigit:]]';
        return (bool)preg_match("/^$hex{8}(-$hex{4}){3}-$hex{12}$/", $guid);
    }

    /**
     * Decode a binary GUID (presumably from ADFS)
     *
     * A GUID is 32 hexadecimal digits with hyphen separators making segments of 8, 4, 4, 4, 12.
     * The first three segments are half the digits at 16 (8+4+4), and the last two segments are the second 16 (4+12).
     * When given a GUID in binary format the first half of digits are grouped by 2, with each group transposing its
     * digits and presenting themselves in reverse order within their respective segments.
     * E.g. once deciphered to plain hexadecimal, 1234567890abcdef becomes 78654321-AB90-EFCD-
     * But the second half are in order so just need a hyphen inserted at the correct spot.
     *
     * @param  string $binaryGuid
     * @return string
     */
    #[PURE]
    public function binToStrGuid($binaryGuid): string
    {
        $hexGuid = bin2hex($binaryGuid);
        $stringGuid = '';
        $segmentStart = 0;
        foreach ([8, 4, 4] as $segmentSize) {
            $segmentStart += $segmentSize;
            $steps = $segmentSize / 2;
            for ($k = 1; $k <= $steps; $k++) {
                $stringGuid .= substr($hexGuid, $segmentStart - 2 * $k, 2);
            }
            $stringGuid .= '-';
        }
        $stringGuid .= substr($hexGuid, 16, 4) . '-' . substr($hexGuid, 20, 12);
        return strtoupper($stringGuid);
    }

    /**
     * @return string[]
     */
    private function getAdditionalGETQueryParameters(): array
    {
        $additionalGetQueryParams = SAMLConfiguration::config()->get('additional_get_query_params');
        if (!is_array($additionalGetQueryParams)) {
            $additionalGetQueryParams = [];
        }

        return $additionalGetQueryParams;
    }
}
