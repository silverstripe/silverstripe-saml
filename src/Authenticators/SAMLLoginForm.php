<?php

namespace SilverStripe\SAML\Authenticators;

use SilverStripe\Control\RequestHandler;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\HiddenField;
use SilverStripe\Forms\FormAction;
use SilverStripe\Security\LoginForm;
use SilverStripe\Security\Security;

/**
 * Class SAMLLoginForm
 *
 * This not very interesting in itself. It's pretty much boiler-plate code to access the authenticator.
 */
class SAMLLoginForm extends LoginForm
{
    /**
     * @var string
     */
    protected $authenticatorClass = SAMLAuthenticator::class;

    /**
     * The name of this login form, to display in the frontend
     * Replaces Authenticator::get_name()
     *
     * @return string
     */
    public function getAuthenticatorName()
    {
        return _t(__CLASS__ . '.AUTHENTICATORNAME', 'SAML');
    }

    /**
     * Constructor
     *
     * @param RequestHandler $controller
     * @param string $name method on the $controller
     */
    public function __construct(RequestHandler $controller, $name)
    {
        $fields = $this->getFormFields();
        $actions = $this->getFormActions();

        $request = $this->getRequest();
        $backURL = $request->requestVar('BackURL') ?: $request->getSession()->get('BackURL');
        if ($backURL) {
            $fields->push(HiddenField::create('BackURL', 'BackURL', $backURL));
        }

        $this->setFormMethod('POST', true);

        if ($this->shouldShowLogoutFields()) {
            $this->setFormAction(Security::logout_url());
        }

        parent::__construct($controller, $name, $fields, $actions);
    }

    protected function getFormFields()
    {
        return FieldList::create();
    }

    protected function getFormActions()
    {
        $actionDetails = $this->shouldShowLogoutFields()
            ? ['logout', _t('SilverStripe\\Security\\Member.BUTTONLOGINOTHER', 'Log in as someone else')]
            : ['doLogin', _t('SilverStripe\\Security\\Member.BUTTONLOGIN', 'Log in')];
        return FieldList::create([FormAction::create(...$actionDetails)]);
    }

    /**
     * @return bool
     */
    protected function shouldShowLogoutFields()
    {
        return (bool)Security::getCurrentUser();
    }
}
