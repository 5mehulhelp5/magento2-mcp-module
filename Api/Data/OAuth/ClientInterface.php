<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Api\Data\OAuth;

/**
 * OAuth 2.1 pre-registered client. Issues MCP access tokens via the
 * authorization_code (PKCE) and refresh_token grants.
 */
interface ClientInterface
{
    public const ID = 'id';
    public const CLIENT_ID = 'client_id';
    public const CLIENT_SECRET_HASH = 'client_secret_hash';
    public const NAME = 'name';
    public const REDIRECT_URIS_JSON = 'redirect_uris_json';
    public const ALLOWED_TOOLS_JSON = 'allowed_tools_json';
    public const AUTH_MODE = 'auth_mode';
    public const SERVICE_ADMIN_USER_ID = 'service_admin_user_id';
    public const ALLOWED_ADMIN_USER_IDS_JSON = 'allowed_admin_user_ids_json';
    public const ALLOWED_ADMIN_ROLE_IDS_JSON = 'allowed_admin_role_ids_json';
    public const DISABLED = 'disabled';
    public const CREATED_AT = 'created_at';

    /**
     * @return int|null
     */
    public function getId(): ?int;

    /**
     * Public client identifier (UUID v4).
     *
     * @return string
     */
    public function getClientId(): string;

    /**
     * @param string $clientId
     * @return self
     */
    public function setClientId(string $clientId): self;

    /**
     * HMAC hash of the plaintext secret; plaintext is never stored.
     *
     * @return string
     */
    public function getClientSecretHash(): string;

    /**
     * @param string $hash
     * @return self
     */
    public function setClientSecretHash(string $hash): self;

    /**
     * @return string
     */
    public function getName(): string;

    /**
     * @param string $name
     * @return self
     */
    public function setName(string $name): self;

    /**
     * Allowed redirect URIs for the authorization-code flow (exact match).
     *
     * @return array<int, string>
     */
    public function getRedirectUris(): array;

    /**
     * @param array $uris
     * @phpstan-param array<int, string> $uris
     * @return self
     */
    public function setRedirectUris(array $uris): self;

    /**
     * MCP tool names this client may request at consent time. The consent
     * screen lets the approving admin tighten this further; the runtime
     * dispatcher enforces both the per-token grant and the admin's role.
     *
     * @return array<int, string>
     */
    public function getAllowedTools(): array;

    /**
     * @param array $tools
     * @phpstan-param array<int, string> $tools
     * @return self
     */
    public function setAllowedTools(array $tools): self;

    /**
     * Mapping mode for OAuth consents. See {@see \Magebit\Mcp\Model\OAuth\AuthMode}.
     *
     * @return \Magebit\Mcp\Model\OAuth\AuthMode
     */
    public function getAuthMode(): \Magebit\Mcp\Model\OAuth\AuthMode;

    /**
     * @param \Magebit\Mcp\Model\OAuth\AuthMode $mode
     * @return self
     */
    public function setAuthMode(\Magebit\Mcp\Model\OAuth\AuthMode $mode): self;

    /**
     * Pinned admin user the client mints tokens on behalf of when
     * {@see getAuthMode()} is SHARED. NULL otherwise (and a misconfiguration in
     * SHARED mode).
     *
     * @return int|null
     */
    public function getServiceAdminUserId(): ?int;

    /**
     * @param int|null $adminUserId
     * @return self
     */
    public function setServiceAdminUserId(?int $adminUserId): self;

    /**
     * Personal-mode whitelist of admin user IDs that may authorize. Empty =
     * no user-level restriction (union with {@see getAllowedAdminRoleIds()}).
     *
     * @return array<int, int>
     */
    public function getAllowedAdminUserIds(): array;

    /**
     * @param array $userIds
     * @phpstan-param array<int, int> $userIds
     * @return self
     */
    public function setAllowedAdminUserIds(array $userIds): self;

    /**
     * Personal-mode whitelist of admin role IDs that may authorize. Empty =
     * no role-level restriction (union with {@see getAllowedAdminUserIds()}).
     *
     * @return array<int, int>
     */
    public function getAllowedAdminRoleIds(): array;

    /**
     * @param array $roleIds
     * @phpstan-param array<int, int> $roleIds
     * @return self
     */
    public function setAllowedAdminRoleIds(array $roleIds): self;

    /**
     * When true, the client is preserved for audit but cannot mint new tokens
     * and cannot refresh existing ones.
     *
     * @return bool
     */
    public function isDisabled(): bool;

    /**
     * @param bool $disabled
     * @return self
     */
    public function setDisabled(bool $disabled): self;

    /**
     * @return string|null
     */
    public function getCreatedAt(): ?string;
}
