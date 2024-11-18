<?php

namespace SilverStripe\SAML\Tests\Helpers;

use Exception;
use OneLogin\Saml2\Auth;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Control\RequestHandler;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\SAML\Services\SAMLConfiguration;

class SAMLHelperTest extends SapphireTest
{
    private function configureHelperForRedirectTesting(bool $withException = false)
    {
        $auth = $this->createStub(Auth::class);
        $login = $auth->expects($this->once())->method('login');
        if ($withException) {
            $login->willThrowException(new Exception('testing'));
        }
        $helper = $this->getMockBuilder(SAMLHelper::class)->onlyMethods(['getSAMLAuth'])->getMock();
        $helper->expects($this->once())->method('getSAMLAuth')->willReturn($auth);
        SAMLConfiguration::config()->set('additional_get_query_params', []);
        return $helper;
    }

    public function testRedirect()
    {
        $helper = $this->configureHelperForRedirectTesting();
        $helper->redirect();
    }

    public function testRedirectWithError()
    {
        $helper = $this->configureHelperForRedirectTesting(true);
        $this->expectException(HTTPResponse_Exception::class);
        $helper->redirect();
    }

    public function testRedirectWithErrorAndRequestHandler()
    {
        $helper = $this->configureHelperForRedirectTesting(true);
        $handler = $this->createStub(RequestHandler::class);
        $handler->expects($this->once())->method('httpError')->with(400);
        $helper->redirect($handler);
    }

    /**
     * @dataProvider guidProvider
     * @param string $guid
     * @param bool   $expected
     */
    public function testValidGuid($guid, $expected)
    {
        $result = SAMLHelper::singleton()->validGuid($guid);
        $this->assertSame($expected, $result);
    }

    /**
     * @return array[]
     */
    public function guidProvider()
    {
        return [
            ['A98C5A1E-A742-4808-96FA-6F409E799937', true],
            ['abcdef01-1111-1111-ffff-abcdef012345', true],
            ['aBcDeF01-1111-1111-ffff-AbCdEf012345', true],
            ['A98C5A1E-1234-5678-9876-ABCDEFGHJIJK', false],
            ['A98C5A1E-1234-56!8-9876-A#CDEFGHJIJK', false],
            ['A98C5A1E-4808-96FA-6F409E799937', false],
            ['foobar', false],
        ];
    }

    public function testBinToStrGuid()
    {
        $result = (new SAMLHelper())->binToStrGuid('thequ!ckbrownf0xjumpsov3rthel4zyd06');
        $this->assertSame('71656874-2175-6B63-6272-6F776E663078', $result);
    }
}
