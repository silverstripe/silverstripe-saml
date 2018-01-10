<?php

namespace SilverStripe\SAML\Helpers;

use SilverStripe\Core\Injector\Injectable;
use SilverStripe\SAML\Services\SAMLConfiguration;
use OneLogin_Saml2_Auth;

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
     * @return OneLogin_Saml2_Auth
     */
    public function getSAMLauth()
    {
        $samlConfig = $this->SAMLConfService->asArray();
        return new OneLogin_Saml2_Auth($samlConfig);
    }

    /**
     * Checks if the string is a valid guid in the format of A98C5A1E-A742-4808-96FA-6F409E799937
     *
     * @param  string $guid
     * @return bool
     */
    public function validGuid($guid)
    {
        if (preg_match('/^[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}?$/', $guid)) {
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
        $hex_guid_to_guid_str .= '-' . substr($hex_guid, 20);
        return strtoupper($hex_guid_to_guid_str);
    }
}
