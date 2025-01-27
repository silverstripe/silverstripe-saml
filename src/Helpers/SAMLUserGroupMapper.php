<?php

namespace SilverStripe\SAML\Helpers;

use Psr\Log\LoggerInterface;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;
use SilverStripe\SAML\Services\SAMLConfiguration;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

class SAMLUserGroupMapper
{
    use Injectable;
    use Configurable;

    /**
     * Group claims field URL defined on IdP
     */
    private static string $group_claims_field = '';

    /**
     * Defines the mapping between the group defined on IdP and the CMS.
     *
     * Note: Groups should be defined on both group_map config and IdP (Azure) before a member can be added. If a
     * group is defined only on Azure, the group will not be created or the member added.
     */
    private static array $group_map = [];

    /**
     * Allow addition of member to a manually-created group which does not exist on IdP
     */
    private static bool $allow_manual_group = false;

    /**
     * Check if group claims field is set and assigns member to group
     *
     * @param [] $attributes
     * @param Member $member
     * @return Member
     */
    public function map($attributes, $member): Member
    {
        $logger = Injector::inst()->get(LoggerInterface::class);
        $groupClaimsField = $this->config()->get('group_claims_field');
        $groupMap = $this->config()->get('group_map');

        $logger->info(sprintf('IdP Attributes: %s', json_encode($attributes, JSON_THROW_ON_ERROR)));

        // Check if group mapping config exists
        if (count($groupMap) <= 0) {
            return $member;
        }

        // Remove member from any group (except if manual group is allowed) before syncing
        if ($this->config()->get('allow_manual_group')) {
            $this->removeMemberFromGroups($member, true);
        } else {
            $this->removeMemberFromGroups($member);
        }

        // Get groups from SAML response
        if (!array_key_exists($groupClaimsField, $attributes)) {
            return $member;
        }

        $groups = $attributes[$groupClaimsField];

        // Check that group claims field has sent through from provider
        if (!isset($groups)) {
            return $member;
        }

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

            // Add member to the group
            $group->Members()->add($member);
        }

        return $member;
    }

    /**
     * Remove the member from current CMS groups except for manual override
     */
    protected function removeMemberFromGroups(Member &$member, bool $allowManualGroup = false)
    {
        if (!$member) {
            return false;
        }

        // Remove all groups associated with this member
        if (!$allowManualGroup) {
            $member->Groups()->removeAll();
            return false;
        }

        $groupMap = $this->config()->get('group_map');

        // Check if group mapping exists
        if (count($groupMap) <= 0) {
            return false;
        }

        // loop through defined group map and remove member
        foreach ($groupMap as $id => $groupTitle) {
            $group = $group = DataObject::get_one(Group::class, [
                '"Group"."Title"' => $groupTitle
            ]);

            if ($group) {
                $group->Members()->removeByID($member->ID);
            }
        }
    }
}
