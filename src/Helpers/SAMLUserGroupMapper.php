<?php

namespace SilverStripe\SAML\Helpers;

use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\ORM\DataObject;
use SilverStripe\SAML\Services\SAMLConfiguration;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

class SAMLUserGroupMapper
{
    use Injectable;
    use Configurable;

    private static string $group_claims_field = '';

    private static array $group_map = [];

    // TODO use this
    private static bool $override_group = false;

    /**
     * @var array
     */
    private static array $dependencies = [
        'SAMLConfService' => '%$' . SAMLConfiguration::class,
    ];

    /**
     * Check if group claims field is set and assigns member to group
     *
     * @param [] $attributes
     * @param Member $member
     * @return Member
     */
    public function map($attributes, $member): Member
    {
        $groupClaimsField = $this->config()->get('group_claims_field');
        $groupMap = $this->config()->get('group_map');

        // Check that group claims field has sent through from provider
        if (!isset($attributes[$groupClaimsField])) {
            return $member;
        }

        // Get groups from saml response
        $groups = $attributes[$groupClaimsField];

        foreach ($groups as $groupID) {
            // Check that group is a valid group with group map
            if (!array_key_exists($groupID, $groupMap)) {
                continue;
            }
            $groupTitle = $groupMap[$groupID];

            // Get Group object by Title
            $group = DataObject::get_one(Group::class, [
                '"Group"."Title"' => $groupTitle
            ]);

            // Create group if it doesn't exist yet
            if (!$group) {
                $group = new Group();
                $group->Title = $groupTitle;
                $group->write();
            }

            $member->Groups()->add($group);
        }

        return $member;
    }
}
