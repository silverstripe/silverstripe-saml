<?php

namespace SilverStripe\SAML\Extensions;

use SilverStripe\Core\Extension;

/**
 * Class GUIDNameIDValidationExtension
 * 
 * Validates a NameID in GUID format.
 */
class GUIDNameIDValidationExtension extends Extension
{
    public function updateNameIDValidation(string $nameID, string $nameIDFormat): bool
    {
        if (preg_match('/^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}?$/i', $nameID)) {
            return true;
        }

        return false;
    }
}
