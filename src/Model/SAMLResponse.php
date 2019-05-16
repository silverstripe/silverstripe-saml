<?php

namespace SilverStripe\SAML\Model;

use SilverStripe\ORM\DataObject;

class SAMLResponse extends DataObject
{
    private static $table_name = 'SAMLResponse';

    private static $db = [
        'ResponseID' => 'Varchar(255)',
        'Expiry' => 'Varchar(12)' // Returned by php-saml as a UTC datetime in unix epoch format
    ];
}