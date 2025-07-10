<?php

namespace SilverStripe\SAML\Helpers;

use OneLogin\Saml2\Auth;
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
     * A mapping of IdP group identifier (of some form - GUID/UUID/ObjectId, Title, etc.) => Silverstripe Group Title
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
     * Check if group claims field is set and assigns member to configured groups
     *
     * @param Auth $auth
     * @param Member $member
     * @param string $errorId
     * @return Member
     */
    public function map(Auth $auth, Member $member, string $errorId): Member
    {
        $config = $this->config();
        $logger = Injector::inst()->get(LoggerInterface::class);
        $groupClaimsField = $config->get('group_claims_field') ?? '';
        $groupMap = $config->get('group_map') ?? [];
        $groupTitles = array_values($groupMap);

        // Create groups that don't exist
        $groups = Group::get()->filter('Title', $groupTitles);
        foreach (array_diff($groupTitles, $groups->column('Title')) as $missingGroup) {
            Group::create()->update(['Title' => $missingGroup])->write();
        }

        // Check if group mapping config exists
        if (empty($groupMap) || empty($groupClaimsField)) {
            $logger->error("[$errorId] Member group assignment is enabled, but the mapping configuration is missing");
            return $member;
        }

        // Remove member from any group (except if manual group is allowed) before syncing
        $memberGroups = $member->Groups();
        if ((bool)$config->get('allow_manual_group')) {
            $memberGroups = $memberGroups->filter('Title', $groupTitles);
        }
        $memberGroups->removeAll();

        // Get groups from SAML response
        $claimedGroups = $auth->getAttribute($groupClaimsField);
        if (is_null($claimedGroups)) {
            $logger->error("[$errorId] Group claim info missing from SAML response");
            return $member;
        }
        if (!is_array($claimedGroups)) {
            $logger->error("[$errorId] Group claim info from SAML response in unexpected format");
            return $member;
        }

        $configuredGroups = array_keys($groupMap);
        $invalidGroups = array_diff($claimedGroups, $configuredGroups);
        if (!empty($invalidGroups)) {
            $logger->warning("[$errorId] SAML response lists groups not in map: " . implode(', ', $invalidGroups));
        }

        $assignedGroups = array_values(array_intersect_key($groupMap, array_flip($claimedGroups)));
        foreach (Group::get()->filter('Title', $assignedGroups) as $group) {
            $memberGroups->add($group);
        }

        return $member;
    }
}
