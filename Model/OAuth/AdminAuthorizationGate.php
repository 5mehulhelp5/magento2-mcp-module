<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Model\OAuth;

use Magento\User\Model\User;

/**
 * Pure-logic decision: may the currently-logged-in Magento admin authorize
 * (or refresh through) the given OAuth client?
 *
 * Reused by both the adminhtml consent controller (which decides before
 * rendering the consent screen) and the public OAuth Authorize controller
 * (which short-circuits on disabled clients before storing a handoff). Kept
 * stateless and side-effect-free so it can be exhaustively unit-tested
 * without a Magento environment.
 */
class AdminAuthorizationGate
{
    /**
     * @param Client $client
     * @param User|null $admin Currently-authenticated admin, or null if the
     *                        session has been lost between handoff and consent.
     * @return AdminAuthorizationDecision
     */
    public function decide(Client $client, ?User $admin): AdminAuthorizationDecision
    {
        if ($client->isDisabled()) {
            return AdminAuthorizationDecision::DENIED_CLIENT_DISABLED;
        }

        $adminUserId = $this->adminUserId($admin);
        if ($admin === null || $adminUserId === null) {
            return AdminAuthorizationDecision::DENIED_NO_ADMIN;
        }

        if ($client->getAuthMode() === AuthMode::SHARED) {
            return $this->decideShared($client, $adminUserId);
        }

        return $this->decidePersonal($client, $admin, $adminUserId);
    }

    /**
     * @param Client $client
     * @param int $adminUserId
     * @return AdminAuthorizationDecision
     */
    private function decideShared(Client $client, int $adminUserId): AdminAuthorizationDecision
    {
        $serviceAdminId = $client->getServiceAdminUserId();
        if ($serviceAdminId === null || $serviceAdminId <= 0) {
            return AdminAuthorizationDecision::MISCONFIGURED_NO_SERVICE_ADMIN;
        }
        return $adminUserId === $serviceAdminId
            ? AdminAuthorizationDecision::ALLOW
            : AdminAuthorizationDecision::DENIED_SHARED_MISMATCH;
    }

    /**
     * @param Client $client
     * @param User $admin
     * @param int $adminUserId
     * @return AdminAuthorizationDecision
     */
    private function decidePersonal(Client $client, User $admin, int $adminUserId): AdminAuthorizationDecision
    {
        $allowedUserIds = $client->getAllowedAdminUserIds();
        $allowedRoleIds = $client->getAllowedAdminRoleIds();

        // Both lists empty → no per-client restriction; ACL on the consent screen
        // and the per-token scope cap still apply downstream.
        if ($allowedUserIds === [] && $allowedRoleIds === []) {
            return AdminAuthorizationDecision::ALLOW;
        }

        if ($allowedUserIds !== [] && in_array($adminUserId, $allowedUserIds, true)) {
            return AdminAuthorizationDecision::ALLOW;
        }

        if ($allowedRoleIds !== [] && $this->adminInAnyRole($admin, $allowedRoleIds)) {
            return AdminAuthorizationDecision::ALLOW;
        }

        return AdminAuthorizationDecision::DENIED_NOT_WHITELISTED;
    }

    /**
     * @param User|null $admin
     * @return int|null
     */
    private function adminUserId(?User $admin): ?int
    {
        if ($admin === null) {
            return null;
        }
        $raw = $admin->getId();
        if (is_int($raw) && $raw > 0) {
            return $raw;
        }
        if (is_string($raw) && ctype_digit($raw) && (int) $raw > 0) {
            return (int) $raw;
        }
        return null;
    }

    /**
     * @param User $admin
     * @param array<int, int> $allowedRoleIds
     * @return bool
     */
    private function adminInAnyRole(User $admin, array $allowedRoleIds): bool
    {
        // User::getRoles() declares array<int> but mocked test doubles and
        // legacy adapters have returned strings; the loop coerces per-row.
        $roles = $admin->getRoles();
        foreach ($roles as $roleId) {
            $rid = $this->coerceRoleId($roleId);
            if ($rid !== null && in_array($rid, $allowedRoleIds, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param mixed $value
     * @return int|null
     */
    private function coerceRoleId(mixed $value): ?int
    {
        if (is_int($value) && $value > 0) {
            return $value;
        }
        if (is_string($value) && ctype_digit($value) && (int) $value > 0) {
            return (int) $value;
        }
        return null;
    }
}
