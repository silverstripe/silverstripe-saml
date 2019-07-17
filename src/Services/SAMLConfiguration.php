<?php

namespace SilverStripe\SAML\Services;

use OneLogin\Saml2\Constants;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Control\Director;
use SilverStripe\Core\Injector\Injector;

/**
 * Class SAMLConfiguration
 *
 * This object's job is to convert configuration from SilverStripe config system
 * into an array that can be consumed by the Onelogin SAML implementation.
 *
 * The configuration tells the IdP and SP how to establish the circle of trust - i.e.
 * how to exchange certificates and which endpoints to use (e.g. see SAMLConfiguration::metadata).
 *
 * https://syncplicity.zendesk.com/hc/en-us/articles/202392814-Single-sign-on-with-ADFS
 *
 * @package activedirectory
 */
class SAMLConfiguration
{
    use Injectable;
    use Configurable;

    /**
     * @var bool
     */
    private static $strict;

    /**
     * @var bool
     */
    private static $debug;

    /**
     * @var array
     */
    private static $SP;

    /**
     * @var array
     */
    private static $IdP;

    /**
     * @var array List of valid AuthN contexts that the IdP can use to authenticate a user. Will be passed to the IdP in
     * every AuthN request (e.g. every login attempt made by a user). The default values should work for ADFS 2.0, but
     * can be overridden if needed.
     */
    private static $authn_contexts;

    /**
     * @config
     * @var bool Whether or not we expect to receive a binary NameID from the IdP. We expect to receive a binary NameID
     * from ADFS, but don't expect it from Azure AD or most other SAML implementations that provide GUIDs.
     *
     * Defaults to true to preserve backwards compatibility (ADFS).
     */
    private static $expect_binary_nameid = true;

    /**
     * @config
     * @var bool Whether or not we allow searching for existing members in the SilverStripe database based on their
     * email address. Marked as insecure because if warnings in developer documentation are not read and understood,
     * this can provide access to the website to people who should not otherwise have access.
     *
     * Defaults to false to prevent looking up members based on email address.
     */
    private static $allow_insecure_email_linking = false;

    /**
     * @config
     * @var bool Decide if GUID should be exposed as an attribute mappable using `GUID` as the claim. This is a feature
     * that is found in other SAML libraries but in an ideal world should not be utilised in favour of the IdP offering
     * the nameid data as another "more stable" attribute.
     * 
     * Note that this data will be effected by:
     *  - The expect_binary_nameid configuration value
     *  - The extension point `updateGuid` on SAMLController
     */
    private static $expose_guid_as_attribute = false;

    /**
     * @config
     * @example ['GET Query Parameter Name' => 'Parameter Value', ... ]
     *
     * @var string[]
     */
    private static $additional_get_query_params = [];

    /**
     * @return array
     */
    public function asArray()
    {
        $conf = [];

        $conf['strict'] = $this->config()->get('strict');
        $conf['debug'] = $this->config()->get('debug');

        // SERVICE PROVIDER SECTION
        $sp = $this->config()->get('SP');

        $spX509Cert = Injector::inst()->convertServiceProperty($sp['x509cert']);
        $spCertPath = Director::is_absolute($spX509Cert)
            ? $spX509Cert
            : sprintf('%s/%s', BASE_PATH, $spX509Cert);
        $spPrivateKey = Injector::inst()->convertServiceProperty($sp['privateKey']);
        $spKeyPath = Director::is_absolute($spPrivateKey)
            ? $spPrivateKey
            : sprintf('%s/%s', BASE_PATH, $spPrivateKey);

        $conf['sp']['entityId'] = Injector::inst()->convertServiceProperty($sp['entityId']);
        $conf['sp']['assertionConsumerService'] = [
            'url' => Injector::inst()->convertServiceProperty($sp['entityId']) . '/saml/acs',
            'binding' => Constants::BINDING_HTTP_POST
        ];
        $conf['sp']['NameIDFormat'] = isset($sp['nameIdFormat']) ?
            $sp['nameIdFormat'] : Constants::NAMEID_TRANSIENT;
        $conf['sp']['x509cert'] = file_get_contents($spCertPath);
        $conf['sp']['privateKey'] = file_get_contents($spKeyPath);

        // IDENTITY PROVIDER SECTION
        $idp = $this->config()->get('IdP');
        $conf['idp']['entityId'] = Injector::inst()->convertServiceProperty($idp['entityId']);
        $conf['idp']['singleSignOnService'] = [
            'url' => Injector::inst()->convertServiceProperty($idp['singleSignOnService']),
            'binding' => Constants::BINDING_HTTP_REDIRECT,
        ];
        if (isset($idp['singleLogoutService'])) {
            $conf['idp']['singleLogoutService'] = [
                'url' => Injector::inst()->convertServiceProperty($idp['singleLogoutService']),
                'binding' => Constants::BINDING_HTTP_REDIRECT,
            ];
        }

        $idpX509Cert = Injector::inst()->convertServiceProperty($idp['x509cert']);
        $idpCertPath = Director::is_absolute($idpX509Cert)
            ? $idpX509Cert
            : sprintf('%s/%s', BASE_PATH, $idpX509Cert);
        $conf['idp']['x509cert'] = file_get_contents($idpCertPath);

        // SECURITY SECTION
        $security = $this->config()->get('Security');
        $signatureAlgorithm = $security['signatureAlgorithm'];

        $authnContexts = $this->config()->get('authn_contexts');
        $disableAuthnContexts = $this->config()->get('disable_authn_contexts');

        if ((bool)$disableAuthnContexts) {
            $authnContexts = false;
        } else {
            if (!is_array($authnContexts)) {
                // Fallback to default contexts if the supplied value isn't valid
                $authnContexts = [
                    'urn:federation:authentication:windows',
                    'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
                    'urn:oasis:names:tc:SAML:2.0:ac:classes:X509',
                ];
            }
        }

        $conf['security'] = [
            /** signatures and encryptions offered */
            // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP will be encrypted.
            'nameIdEncrypted' => true,
            // Indicates whether the <samlp:AuthnRequest> messages sent by this SP will be signed. [Metadata of the
            // SP will offer this info]
            'authnRequestsSigned' => true,
            // Indicates whether the <samlp:logoutRequest> messages sent by this SP will be signed.
            'logoutRequestSigned' => true,
            // Indicates whether the <samlp:logoutResponse> messages sent by this SP will be signed.
            'logoutResponseSigned' => true,
            'signMetadata' => false,
            /** signatures and encryptions required **/
            // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest>
            // and <samlp:LogoutResponse> elements received by this SP to be signed.
            'wantMessagesSigned' => false,
            // Indicates a requirement for the <saml:Assertion> elements received by
            // this SP to be signed. [Metadata of the SP will offer this info]
            'wantAssertionsSigned' => true,
            // Indicates a requirement for the NameID received by
            // this SP to be encrypted.
            'wantNameIdEncrypted' => false,

            // Algorithm that the toolkit will use on signing process. Options:
            //  - 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            //  - 'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
            //  - 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
            //  - 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
            //  - 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
            'signatureAlgorithm' => $signatureAlgorithm,

            // Authentication context.
            // Set to false and no AuthContext will be sent in the AuthNRequest,
            // Set true or don't present thi parameter and you will get an AuthContext
            // 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
            // Set an array with the possible auth context values:
            // array ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'),
            'requestedAuthnContext' => $authnContexts,

            // Indicates if the SP will validate all received xmls.
            // (In order to validate the xml, 'strict' and 'wantXMLValidation' must be true).
            'wantXMLValidation' => true,
        ];

        return $conf;
    }
}
