<?php

namespace SilverStripe\SAML\Tests\Helpers;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\Core\Config\Config;
use SilverStripe\SAML\Services\SAMLConfiguration;

class SAMLHelperTest extends SapphireTest
{
    /**
     * @dataProvider guidProvider
     * @param string $guid
     * @param bool   $expected
     */
    public function testValidGuid($guid, $expected)
    {
        Config::modify()->set(SAMLConfiguration::class, 'validate_nameid', true);
        $result = SAMLHelper::singleton()->validateNameID($guid, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
        $this->assertSame($expected, $result);
    }

    /**
     * @return array[]
     */
    public function guidProvider()
    {
        return [
            ['A98C5A1E-A742-4808-96FA-6F409E799937', true],
            ['aBcDeF01-1111-1111-ffff-AbCdEf012345', true],
            ['A98C5A1E-1234-5678-9876-ABCDEFGHJIJK', false],
            ['A98C5A1E-1234-56!8-9876-A#CDEFGHJIJK', false],
            ['A98C5A1E-4808-96FA-6F409E799937', false],
            ['foobar', false],
        ];
    }

    /**
     * @testdox A long NameID that would exceed the max of a Member's GUID field should fail validation.
     */
    public function testLongNameIDFails()
    {
        $result = SAMLHelper::singleton()->validateNameID(
            'my-excessively-long-nameid-which-is-quite-ridiculous', // 52 chars
            'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
        );
        $this->assertFalse($result);
    }

    public function testBinToStrGuid()
    {
        $result = SAMLHelper::singleton()->binToStrGuid('thequ!ckbrownf0xjumpsov3rthel4zyd06');
        $this->assertSame('71656874-2175-6B63-6272-6F776E6630786A756D70736F7633727468656C347A79643036', $result);
    }
}
