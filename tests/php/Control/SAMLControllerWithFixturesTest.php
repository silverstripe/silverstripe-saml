<?php

namespace SilverStripe\SAML\Tests\Control;

use Exception;
use OneLogin\Saml2\Auth;
use Psr\Log\LoggerInterface;
use ReflectionClass;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\ORM\ValidationException;
use SilverStripe\SAML\Control\SAMLController;
use SilverStripe\SAML\Exceptions\AcsFailure;
use SilverStripe\SAML\Helpers\SAMLHelper;
use SilverStripe\SAML\Model\SAMLResponse;
use SilverStripe\SAML\Services\SAMLConfiguration;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

class SAMLControllerWithFixturesTest extends SapphireTest
{
    private const FIXTURE_MEMBERS = 2 + 1; // number of members via fixture file + ADMIN via SapphireTest setUp

    private const DEFAULT_CLAIMS = [
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname' => 'FirstName',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname' => 'Surname',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' => 'Email',
    ];

    private const DEFAULT_CONFIG = [
        'expect_binary_nameid' => true,
        'validate_nameid_as_guid' => true,
        'expose_guid_as_attribute' => false,
        'allow_insecure_email_linking' => false,
        'login_persistent' => false,
    ];

    private const DEFAULT_GUID = '12345678-1234-asdf-0987-12345678asdf';

    private const DEFAULT_RETURNS = [
        'binToStrGuid' => self::DEFAULT_GUID,
        'validGuid' => true,
        'processResponse' => null, // string|null throws Exception when string
        'getLastErrorReason' => null, // string|null
        'isAuthenticated' => true,
        'getLastMessageId' => 'good',
        'getLastAssertionNotOnOrAfter' => '2024-11-01 15:07:33',
        'getNameId' => self::DEFAULT_GUID,
        'getAttributes' => [
            'FirstName' => 'Test',
            'Surname' => 'User',
            'Email' => 'test@test.test',
        ],
    ];

    protected static $fixture_file = 'membersAndResponses.yml';

    public function setUp(): void
    {
        parent::setUp();
        $this->logOut(); // ADMIN is logged in by default when using a database in testing (e.g. with fixtures)
    }

    public function testReplayAttack()
    {
        $auth = $this->createStub(Auth::class);
        $auth->method('getLastMessageId')->willReturn('used');
        $auth->method('getLastAssertionNotOnOrAfter')->willReturn('2024-11-01 15:07:33');

        $request = $this->createStub(HTTPRequest::class);
        $request->method('getIP')->willReturn('000.123.456.789');

        $controller = new SAMLController();
        $controller->setRequest($request);
        $reflection = new ReflectionClass(SAMLController::class);
        $method = $reflection->getMethod('checkForReplayAttack');

        $this->expectException(AcsFailure::class);
        $this->expectExceptionMessage(
            'SAML replay attack detected! Response ID "used", expires "2024-11-01 15:07:33", client IP'
            . ' "000.123.456.789"'
        );

        $result = $method->invokeArgs($controller, [$auth]);

        $this->assertTrue($result);
        $this->assertCount(1, SAMLResponse::get()->filter('ResponseID', 'used'));
    }

    public function testReplayCheck()
    {
        $auth = $this->createStub(Auth::class);
        $auth->method('getLastMessageId')->willReturn('current');
        $auth->method('getLastAssertionNotOnOrAfter')->willReturn('2024-11-01 15:07:33');

        $controller = new SAMLController();
        $reflection = new ReflectionClass(SAMLController::class);
        $method = $reflection->getMethod('checkForReplayAttack');

        $method->invokeArgs($controller, [$auth]);

        $this->assertCount(1, SAMLResponse::get()->filter('ResponseID', 'current'), 'The response ID should be logged');
    }

    /**
     * The ACS function flows based mainly on configuration. The moves all the mocking and configuration setup to a
     * reusable spot.
     *
     * Set `$claims[$theClaim] = null` to unset it.
     * Same with skipping values from `getAttributes` via $returns.
     *
     * @param array $claims config for Member.claims_field_mappings
     * @param array $config configuration for {@see SAMLConfiguration}
     * @param array $returns PHPUnit method stub returns
     * @return SAMLController
     */
    private function configureACS(array $claims = [], array $config = [], array $returns = []): SAMLController
    {
        $claims = array_filter(array_merge(self::DEFAULT_CLAIMS, $claims), null);
        Member::config()->set('claims_field_mappings', $claims);
        $claimValues = array_merge(self::DEFAULT_RETURNS['getAttributes'], $returns['getAttributes'] ?? []);
        $returns = array_merge(self::DEFAULT_RETURNS, $returns, ['getAttributes' => $claimValues]);
        Director::config()->set('alternate_base_url', 'https://running.test');
        $samlConfigConfig = SAMLConfiguration::config();
        foreach (array_merge(self::DEFAULT_CONFIG, $config) as $key => $value) {
            $samlConfigConfig->set($key, $value);
        }
        Member::config()->set('claims_field_mappings', $claims);

        $helper = $this->createStub(SAMLHelper::class);
        $auth = $this->createStub(Auth::class);
        $request = $this->createStub(HTTPRequest::class);
        $session = $this->createStub(Session::class);
        $logger = $this->createMock(LoggerInterface::class);
        $helper->method('getSAMLAuth')->willReturn($auth);

        $helper->method('binToStrGuid')->willReturn($returns['binToStrGuid']);
        $helper->method('validGuid')->willReturn($returns['validGuid']);
        $auth->method('getLastErrorReason')->willReturn($returns['getLastErrorReason']);
        $auth->method('isAuthenticated')->willReturn($returns['isAuthenticated']);
        $auth->method('getLastMessageId')->willReturn($returns['getLastMessageId']);
        $auth->method('getLastAssertionNotOnOrAfter')->willReturn($returns['getLastAssertionNotOnOrAfter']);
        $auth->method('getNameId')->willReturn($returns['getNameId']);
        $auth->method('getAttributes')->willReturn(array_filter(
            array_combine(
                array_keys($claims),
                array_map(fn($name) => array_filter([$returns['getAttributes'][$name] ?? null], null), $claims)
            ),
            null
        ));
        if (is_string($returns['processResponse'])) {
            $auth->method('processResponse')->willThrowException(new Exception($returns['processResponse'], 369));
        }

        $auth->method('getSessionIndex')->willReturn('anSesh');
        $request->method('getSession')->willReturn($session);
        $session->method('get')->with('BackURL')->willReturn('/another/page');
        Injector::inst()->registerService($helper, SAMLHelper::class);
        Injector::inst()->registerService($logger, LoggerInterface::class);


        $controller = new SAMLController();
        $controller->setRequest($request);

        return $controller;
    }

    public function testACSGoodHappyPath()
    {
        $this->assertCount(0, Member::get()->filter('GUID', self::DEFAULT_GUID));

        $controller = $this->configureACS();
        $controller->getLogger()->expects($this->never())->method($this->anything());
        $response = $controller->acs();

        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('https://running.test/another/page', $response->getHeader('location'));
        $members = Member::get()->filter('GUID', self::DEFAULT_GUID);
        $this->assertCount(1, $members);
        $member = $members->first();
        $this->assertSame('Test', $member->FirstName);
        $this->assertSame('User', $member->Surname);
        $this->assertSame('test@test.test', $member->Email);
        $this->assertCount(self::FIXTURE_MEMBERS + 1, Member::get(), 'A new member should have been created');
    }

    // It is unclear whether one would expect to go back to where they came from (e.g. via SAMLMiddleware), or to
    // the log in page when ACS fails - so asserting the response location header is not happening for all bad outcomes.
    // It is covered in the test above for good outcomes, so is simply not repeated.

    public function testACSBadWithResponseException()
    {
        $controller = $this->configureACS(returns: ['processResponse' => 'Failure to Assertify!']);
        $controller->getLogger()->expects($this->once())->method('error')->with(
            $this->stringContains('] [code: 369] Failure to Assertify! (')
        );
        $response = $controller->acs();
        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertCount(self::FIXTURE_MEMBERS, Member::get(), 'No new members should exist');
    }

    public function testACSBadWithResponseError()
    {
        $controller = $this->configureACS(returns: ['getLastErrorReason' => 'Assertion error!']);
        $controller->getLogger()->expects($this->once())->method('error')->with(
            $this->stringEndsWith('] Assertion error!')
        );
        $response = $controller->acs();
        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertCount(self::FIXTURE_MEMBERS, Member::get(), 'No new members should exist');
    }

    public function testACSBadWithAuthenticationFailure()
    {
        $controller = $this->configureACS(returns: ['isAuthenticated' => false]);
        $response = $controller->acs();
        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertCount(self::FIXTURE_MEMBERS, Member::get(), 'No new members should exist');
        $this->assertNull(Security::getCurrentUser());
    }

    public function testACSBadWithReplayAttack()
    {
        $controller = $this->configureACS(
            config: ['expect_binary_nameid' => false],
            returns: ['getNameId' => '12345678-0987-asdf-12345678asdf', 'getLastMessageId' => 'used']
        );
        $response = $controller->acs();
        $this->assertCount(self::FIXTURE_MEMBERS, Member::get(), 'No new members should exist');
        $this->assertNull(Security::getCurrentUser());
    }

    public function testACSBadWithInvalidGUID()
    {
        $guid = '12dollarsAndFiftyCents';
        $controller = $this->configureACS(returns: ['binToStrGuid' => $guid, 'validGuid' => false]);
        $controller->getLogger()->expects($this->once())->method('error')->with(
            $this->stringEndsWith("Invalid GUID '12dollarsAndFiftyCents' received from IdP")
        );
        $response = $controller->acs();
        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertCount(0, Member::get()->filter('GUID', $guid));
    }

    public function testACSBadWithBinaryEncode()
    {
        $guid = base64_encode('all printable characters');
        $controller = $this->configureACS(returns: ['getNameId' => $guid]);
        $controller->getLogger()->expects($this->once())->method('error')->with(
            $this->stringEndsWith('NameID from IdP is not a binary GUID')
        );
        $response = $controller->acs();
        $this->assertInstanceOf(HTTPResponse::class, $response);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertCount(0, Member::get()->filter('GUID', 'all printable characters'));
    }

    public function testACSGoodWithNonGuid()
    {
        $controller = $this->configureACS(
            config: ['expect_binary_nameid' => false, 'validate_nameid_as_guid' => false],
            returns: ['getNameId' => 'GitHub@Nightjar', 'validGuid' => false]
        );
        $response = $controller->acs();
        $member = Member::get()->filter('GUID', 'GitHub@Nightjar');
        $this->assertCount(1, $member);
    }

    public function testACSGoodWithExistingMember()
    {
        $controller = $this->configureACS(
            config: ['expect_binary_nameid' => false],
            returns: [
                'getNameId' => '12345678-0987-asdf-12345678asdf',
                'getAttributes' => [
                    'FirstName' => 'Some',
                    'Surname' => 'One-Else',
                    'Email' => 'Some.One@test.test'
                ]
            ],
        );
        $response = $controller->acs();
        $this->assertCount(self::FIXTURE_MEMBERS, Member::get(), 'No new members should exist');
        $member = Security::getCurrentUser();
        $this->assertNotNull($member);
        $this->assertSame('Some', $member->FirstName);
        $this->assertSame('One-Else', $member->Surname);
        $this->assertSame('Some.One@test.test', $member->Email);
        $this->assertSame('mi_NZ', $member->Locale, 'Other properties should be unchanged');
    }

    public function testACSBadMemberCollision()
    {
        $this->expectException(ValidationException::class);
        $controller = $this->configureACS(returns: ['getAttributes' => ['Email' => 'Some.One@test.test']]);
        $controller->acs();
        $this->assertNull(Security::getCurrentUser());
    }

    public function testACSGoodMemberLinkByEmail()
    {
        $controller = $this->configureACS(
            config: [
                'allow_insecure_email_linking' => true,
                'expect_binary_nameid' => false,
            ],
            returns: [
                'getNameId' => 'deadbeef-0123-4567-7654-3210feebdaed',
                'getAttributes' => ['Email' => 'existing@account.test'],
            ]
        );
        $controller->acs();
        $this->assertCount(self::FIXTURE_MEMBERS, Member::get(), 'No new members should exist');
        $member = Security::getCurrentUser();
        $this->assertNotNull($member);
        $this->assertSame('deadbeef-0123-4567-7654-3210feebdaed', $member->GUID);
        $this->assertSame('existing@account.test', $member->Email);
        $this->assertSame('Test', $member->FirstName);
        $this->assertSame('User', $member->Surname);
    }

    public function testACSGoodClaimsMap()
    {
        $controller = $this->configureACS(
            claims: ['urn:pretend:claim:locale' => 'Locale'],
            returns: ['getAttributes' => ['Locale' => 'mi_NZ']]
        );
        $controller->acs();
        // ensure we're not testing an existing user with the same Locale
        $this->assertCount(self::FIXTURE_MEMBERS + 1, Member::get(), 'A new member should exist');
        $member = Security::getCurrentUser();
        $this->assertSame('test@test.test', $member->Email);
        $this->assertSame('mi_NZ', $member->Locale);
    }

    public function testACSGoodUnknownClaimLogsAWarning()
    {
        $controller = $this->configureACS(claims: ['urn:pretend:claim:locale' => 'Locale']);
        $controller->getLogger()->expects($this->once())->method('warning')->with($this->stringEndsWith(
            '] Claim rule \'urn:pretend:claim:locale\' configured in SAMLMemberExtension.claims_field_mappings, but'
            . ' wasn\'t passed through. Please check IdP claim rules.'
        ));
        $controller->acs();
    }

    public function testACSGoodClaimsGuidUsedForAnotherProperty()
    {
        $guid = 'probably.UPN.instead.of.ObjectId@EntraId.test';
        $controller = $this->configureACS(
            claims: ['GUID' => 'Email', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress' => null],
            config: ['expect_binary_nameid' => false, 'expose_guid_as_attribute' => true],
            returns: ['getNameId' => $guid],
        );
        $controller->acs();
        $member = Security::getCurrentUser();
        $this->assertSame($guid, $member->Email);
    }
}
