<?php

namespace App\Tests\SSO;

use SilverStripe\Dev\TestOnly;
use SilverStripe\SAML\Helpers\SAMLUserGroupMapper;

class SAMLUserGroupMapperFake extends SAMLUserGroupMapper implements TestOnly
{
    private static string $group_claims_field = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';

    private static array $group_map = [
        'de074ca9-d0f4-43dd-b1f3-e1bb7456ba30' => 'Administrators',
        'ede43371-7166-44cd-b9ee-2221e0d4f74b' => 'Branch finder',
        '060126ff-4aae-4f23-bd58-10ba8b7f192c' => 'Content publishers',
    ];
}
