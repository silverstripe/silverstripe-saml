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

    /**
     * @var string
     */
    private static $group_claims_field;

    /**
     * @var array
     */
    private static $dependencies = [
        'SAMLConfService' => '%$' . SAMLConfiguration::class,
    ];

    public function map($attributes, $member): Member
    {
        $groups = $this->config()->get('group_claims_field');

        if (!isset($attributes[$groups])) {
            return $member;
        }

        // Get groups from saml response
        $groupTitles = $attributes[$groups];

        foreach ($groupTitles as $groupTitle) {
            // Get Group object by Title
            // TODO: Title for Group should be unique
            $group = DataObject::get_one(Group::class, [
                '"Group"."Title"' => $groupTitle
            ]);

            if (!$group) {
                $group = new Group();
                $group->Title = $groupTitle;
                $group->write();
            }

            $member->write();
            $member->Groups()->add($group);
        }

        return $member;
    }
}
