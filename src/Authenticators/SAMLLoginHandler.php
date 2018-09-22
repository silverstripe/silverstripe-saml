<?php

namespace SilverStripe\SAML\Authenticators;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Control\RequestHandler;
use SilverStripe\SAML\Helpers\SAMLHelper;

class SAMLLoginHandler extends RequestHandler
{
    private static $url_handlers = [
        '' => 'login',
    ];

    private static $allowed_actions = [
        'login',
        'LoginForm'
    ];

    private static $dependencies = [
        'helper' => '%$' . SAMLHelper::class
    ];

    /**
     * @var SAMLAuthenticator
     */
    protected $authenticator;

    /**
     * @var SAMLHelper
     */
    protected $helper;

    /**
     * Link to this handler
     *
     * @var string
     */
    protected $link = null;

    /**
     * @param string $link The URL to recreate this request handler
     * @param SAMLAuthenticator $authenticator The authenticator to use
     */
    public function __construct($link, SAMLAuthenticator $authenticator)
    {
        $this->link = $link;
        $this->authenticator = $authenticator;
        parent::__construct();
    }

    /**
     * URL handler for the log-in screen
     *
     * @return array
     */
    public function login()
    {
        return [
            'Form' => $this->loginForm(),
        ];
    }

    public function loginForm()
    {
        return SAMLLoginForm::create(
            $this,
            get_class($this->authenticator),
            'LoginForm'
        );
    }

    /**
     * Return a link to this request handler.
     * The link returned is supplied in the constructor
     *
     * @param null|string $action
     * @return string
     */
    public function Link($action = null)
    {
        $link = Controller::join_links($this->link, $action);
        $this->extend('updateLink', $link, $action);
        return $link;
    }

    /**
     * Login form handler method
     *
     * This method is called when the user finishes the login flow
     *
     * @param array $data Submitted data
     * @param SAMLLoginForm $form
     * @param HTTPRequest $request
     * @return void This method never returns anything - it just redirects the user to the IdP
     * @throws HTTPResponse_Exception
     */
    public function doLogin($data, SAMLLoginForm $form, HTTPRequest $request)
    {
        $backURL = (isset($data['BackURL']) ? $data['BackURL'] : null);
        $this->helper->redirect($this, $request, $backURL);
    }

    /**
     * @return SAMLHelper
     */
    public function getHelper()
    {
        return $this->helper;
    }

    /**
     * Sets the SAMLHelper that this login handler should use to redirect users to the IdP
     *
     * @param SAMLHelper $helper
     * @return $this
     */
    public function setHelper(SAMLHelper $helper)
    {
        $this->helper = $helper;
        return $this;
    }
}
