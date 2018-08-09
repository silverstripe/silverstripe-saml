<?php
namespace SilverStripe\SAML\Middleware;

use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\Security\Security;

class SAMLMiddleware implements HTTPMiddleware
{
    use Configurable;

    /**
     * @var bool Whether this middleware is enabled or not
     * @config
     */
    private static $enabled = false;

    /**
     * @var array A list of URLs to be excluded from processing via this middleware. These URLs are passed through
     * preg_match(), so regular expressions are acceptable. The default URLs include:
     * - Any URL under Security/
     * - Any URL under saml/
     */
    private static $excluded_urls = [
        '/^Security/i',
        '/^saml/i'
    ];

    /**
     * Processes the given request. If the middleware is enabled, the URL pattern does not match an exclusion pattern,
     * and the user is not logged in, then they are shipped off to the SAML Identity Provider (IdP) to authenticate.
     *
     * Note: This middleware is always included in all requests, but is not enabled by default.
     *
     * @param HTTPRequest $request
     * @param callable $delegate
     * @return \SilverStripe\Control\HTTPResponse|void
     */
    public function process(HTTPRequest $request, callable $delegate)
    {
        // If the middleware isn't enabled, immediately stop processing and pass on to other delegates
        if (!$this->isEnabled()) {
            return $delegate($request);
        }

        // Check the URL to see if it matches an exclusion rule - if so, stop processing and pass on to other delegates
        if ($this->checkExcludedUrl($request)) {
            return $delegate($request);
        }

        // Don't redirect on CLI
        if (Director::is_cli()) {
            return $delegate($request);
        }

        // If the user is already logged in, stop processing and pass on to other delegates
        if (Security::getCurrentUser()) {
            return $delegate($request);
        }

        // If we get this far, then the middleware is enabled, doensdoesn't match an exclusion rule, and the user is not
        // logged in. Therefore, we should redirect them to the identity provider to log in, and set the back URL to the
        // current URL for when they successfully return
        /** @var SAMLHelper $helper */
        $helper = Injector::inst()->get(SAMLHelper::class);
        $helper->redirect(null, $request, $request->getURL(true));
    }

    /**
     * @param HTTPRequest $request The current request
     * @return bool true if the current URL should be excluded from having this middleware run
     */
    protected function checkExcludedUrl(HTTPRequest $request)
    {
        $urls = $this->getExcludedUrls();
        $currentRelativeUrl = $request->getURL(true);

        foreach ($urls as $pattern) {
            if (preg_match($pattern, $currentRelativeUrl)) {
                return true;
            }
        }

        // If no URLs match, then the current URL isn't excluded and should be processed
        return false;
    }

    /**
     * @return array The list of all excluded URLs
     */
    protected function getExcludedUrls()
    {
        return $this->config()->excluded_urls;
    }

    /**
     * @return bool true if this middleware is enabled, false if it's not enabled
     */
    protected function isEnabled()
    {
        return $this->config()->enabled;
    }
}