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
     * Defines the mapping between the group defined on IdP and the CMS
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

        // Get groups from saml response
        $groups = $attributes[$groupClaimsField];

        // log group mapping details
        $logger->info('----- Group mapping before sync -----');
        $logger->info(sprintf('Member ID: %s', $member?->ID));
        $logger->info(
            sprintf(
                'Current member groups: %s',
                json_encode($member->Groups()->column('Title'), JSON_THROW_ON_ERROR)
            )
        );
        $logger->info(sprintf('Group (IdP) claims field: %s', $groupClaimsField));
        $logger->info(sprintf('Group mapping: %s', json_encode($groupMap, JSON_THROW_ON_ERROR)));
        $logger->info(sprintf('IdP Attributes: %s', json_encode($attributes, JSON_THROW_ON_ERROR)));

        // Check that group claims field has sent through from provider
        if (!isset($groups)) {
            return $member;
        }

        // Check if group mapping exists
        if (count($groupMap) <= 0) {
            return $member;
        }

        // Remove member from any group before group assignment except manual group
        if ($this->config()->get('allow_manual_group')) {
            $this->removeMemberFromGroups($member, true);
        } else {
            $this->removeMemberFromGroups($member);
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

        // log group mapping details
        $logger->info('----- Group mapping after sync -----');
        $logger->info(sprintf('Member ID: %s', $member?->ID));
        $logger->info(
            sprintf(
                'Current member groups: %s',
                json_encode($member->Groups()->column('Title'), JSON_THROW_ON_ERROR)
            )
        );

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
