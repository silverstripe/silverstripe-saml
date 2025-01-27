<?php

namespace App\Tests\SSO;

use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class SAMLUserGroupMapperTest extends SapphireTest
{
    public const AZURE_GROUP_ID_ADMIN = 'de074ca9-d0f4-43dd-b1f3-e1bb7456ba30';
    public const AZURE_GROUP_ID_BRANCH_FINDER = 'ede43371-7166-44cd-b9ee-2221e0d4f74b';
    public const AZURE_GROUP_ID_CONTENT_PUBLISHER = '060126ff-4aae-4f23-bd58-10ba8b7f192c';

    protected static $fixture_file = 'SAMLUserGroupMapperTest.yml';

    private Member $member;

    private SAMLUserGroupMapperFake $mapper;

    /**
     * @inheritDoc
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->member = $this->objFromFixture(Member::class, 'member_1');
        $this->mapper = SAMLUserGroupMapperFake::singleton();
    }

    /**
     * Check if we are getting correct user group associated to this member
     *
     * @dataProvider userGroupMapCountProvider
     */
    public function testUserGroupMapCount(int $count, array $attributes): void
    {
        $this->mapper->map($attributes, $this->member);

        $this->assertEquals($count, $this->member->Groups()->count());
    }

    /**
     * Check if a member is removed from a group defined on IdP
     */
    public function testUserRemovedFromStaleGroup(): void
    {
        // member has existing group defined on IdP group mapping
        $member = $this->objFromFixture(Member::class, 'member_2');
        $this->assertEquals(2, $member->Groups()->count());
        $this->assertNotNull($member->Groups()->find('Title:PartialMatch', 'Branch Finder'));

        // define mock group attributes
        $attributes = [
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => [
                self::AZURE_GROUP_ID_ADMIN,
                self::AZURE_GROUP_ID_CONTENT_PUBLISHER,
            ],
        ];

        // apply IdP mapping
        $this->mapper->map($attributes, $member);
        $this->assertEquals(2, $member->Groups()->count());
        $this->assertNull($member->Groups()->find('Title:PartialMatch', 'Branch Finder'));
    }

    /**
     * Check if a member can retain manual group
     */
    public function testUserRetainManualGroup(): void
    {
        $member = $this->objFromFixture(Member::class, 'member_2');
        $this->assertEquals(2, $member->Groups()->count());

        // manual group associated to this member
        $this->assertNotNull($member->Groups()->find('Title:PartialMatch', 'Manual group'));

        // define mock group attributes
        $attributes = [
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => [
                self::AZURE_GROUP_ID_ADMIN,
                self::AZURE_GROUP_ID_CONTENT_PUBLISHER,
            ],
        ];

        // allow manual group
        Config::modify()->set(SAMLUserGroupMapperFake::class, 'allow_manual_group', true);

        // apply IdP mapping
        $this->mapper->map($attributes, $member);
        $this->assertEquals(3, $member->Groups()->count());

        // manual group still exists on this member
        $this->assertNotNull($member->Groups()->find('Title:PartialMatch', 'Manual group'));
    }

    /**
     * Check when IdP removes a member from a group
     */
    public function testUserGroupMapIfMemberIsRemoved(): void
    {
        // member has no initial group
        $this->assertEquals(0, $this->member->Groups()->count());

        // define mock group attributes
        $attributes = [
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => [
                self::AZURE_GROUP_ID_ADMIN,
                self::AZURE_GROUP_ID_CONTENT_PUBLISHER,
                self::AZURE_GROUP_ID_BRANCH_FINDER,
            ],
        ];

        $attributes2 = [
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => [
                self::AZURE_GROUP_ID_ADMIN,
                self::AZURE_GROUP_ID_CONTENT_PUBLISHER,
            ],
        ];

        // apply group mapping to member
        // apply IdP mapping
        $this->mapper->map($attributes, $this->member);
        $this->assertEquals(3, $this->member->Groups()->count());

        // assert if member is removed on a group on IdP
        $this->mapper->map($attributes2, $this->member);
        $this->assertEquals(2, $this->member->Groups()->count());
    }

    /**
     * Mock attributes from IdP
     */
    public function userGroupMapCountProvider(): array
    {
        // All attributes match defined group mapping
        $attributes1 = [
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => [
                self::AZURE_GROUP_ID_ADMIN,
                self::AZURE_GROUP_ID_CONTENT_PUBLISHER,
                self::AZURE_GROUP_ID_BRANCH_FINDER,
            ],
        ];

        // Member not added to all groups
        $attributes2 = [
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => [
                self::AZURE_GROUP_ID_ADMIN,
                self::AZURE_GROUP_ID_CONTENT_PUBLISHER,
            ],
        ];

        // Additional group added not part of defined group mapping
        $attributes3 = [
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role' => [
                self::AZURE_GROUP_ID_ADMIN,
                self::AZURE_GROUP_ID_CONTENT_PUBLISHER,
                '11111111-1111-1111-1111-111111111111',
            ],
        ];

        return [
            [3, $attributes1],
            [2, $attributes2],
            [2, $attributes3],
        ];
    }
}
