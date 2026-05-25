<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Model\OAuth;

/**
 * Result of {@see AdminAuthorizationGate::decide()}.
 *
 * Each case carries an OAuth-2.1 error code and a redirect-safe description,
 * so the controllers can render a uniform `error=…&error_description=…` response
 * for non-allow outcomes without re-deriving the wording per call-site.
 */
enum AdminAuthorizationDecision: string
{
    case ALLOW = 'allow';
    case DENIED_NO_ADMIN = 'denied_no_admin';
    case DENIED_NOT_WHITELISTED = 'denied_not_whitelisted';
    case DENIED_SHARED_MISMATCH = 'denied_shared_mismatch';
    case DENIED_CLIENT_DISABLED = 'denied_client_disabled';
    case MISCONFIGURED_NO_SERVICE_ADMIN = 'misconfigured_no_service_admin';

    /**
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this === self::ALLOW;
    }

    /**
     * OAuth-2.1 `error` token to return when this decision is non-allow.
     *
     * @return string
     */
    public function oauthError(): string
    {
        return match ($this) {
            self::ALLOW => '',
            self::DENIED_NO_ADMIN,
            self::DENIED_NOT_WHITELISTED,
            self::DENIED_SHARED_MISMATCH => 'access_denied',
            self::DENIED_CLIENT_DISABLED,
            self::MISCONFIGURED_NO_SERVICE_ADMIN => 'server_error',
        };
    }

    /**
     * Operator-facing description suitable for an `error_description` query param.
     *
     * @return string
     */
    public function description(): string
    {
        return match ($this) {
            self::ALLOW => '',
            self::DENIED_NO_ADMIN
                => 'Admin session lost during approval.',
            self::DENIED_NOT_WHITELISTED
                => 'Admin user not permitted to authorize this client.',
            self::DENIED_SHARED_MISMATCH
                => 'Only the pinned service admin may authorize this client.',
            self::DENIED_CLIENT_DISABLED
                => 'This OAuth client has been disabled by an operator.',
            self::MISCONFIGURED_NO_SERVICE_ADMIN
                => 'This OAuth client is configured for shared mode but has no service admin pinned.',
        };
    }
}
