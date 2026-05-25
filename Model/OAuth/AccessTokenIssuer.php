<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Model\OAuth;

use Magebit\Mcp\Exception\OAuthException;
use Magebit\Mcp\Model\Auth\TokenGenerator;
use Magebit\Mcp\Model\Auth\TokenHasher;
use Magebit\Mcp\Model\Config\ModuleConfig;
use Magebit\Mcp\Model\Config\Source\ReauthBehavior;
use Magebit\Mcp\Model\TokenFactory;
use Magebit\Mcp\Model\TokenRepository;
use RuntimeException;

/**
 * Mints an OAuth 2.1 access-token + refresh-token pair. The access token is a
 * row in `magebit_mcp_token` carrying an `oauth_client_id` linkback, so it
 * flows through the same {@see \Magebit\Mcp\Model\Auth\TokenAuthenticator} as
 * CLI-issued bearers. Plaintexts are returned exactly once via
 * {@see IssuedTokenPair}; only HMAC hashes are persisted.
 */
class AccessTokenIssuer
{
    /**
     * @param TokenFactory $tokenFactory
     * @param TokenRepository $tokenRepository
     * @param RefreshTokenFactory $refreshTokenFactory
     * @param RefreshTokenRepository $refreshTokenRepository
     * @param TokenGenerator $tokenGenerator
     * @param TokenHasher $tokenHasher
     * @param ModuleConfig $config
     * @param ToolGrantResolver $toolGrantResolver
     */
    public function __construct(
        private readonly TokenFactory $tokenFactory,
        private readonly TokenRepository $tokenRepository,
        private readonly RefreshTokenFactory $refreshTokenFactory,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly TokenGenerator $tokenGenerator,
        private readonly TokenHasher $tokenHasher,
        private readonly ModuleConfig $config,
        private readonly ToolGrantResolver $toolGrantResolver
    ) {
    }

    /**
     * @param int $oauthClientId
     * @param string $oauthClientName
     * @param int $adminUserId
     * @param bool $allowWrites
     * @param array<int, string>|null $toolNames
     * @param int|null $parentRefreshTokenId
     * @return IssuedTokenPair
     */
    public function issue(
        int $oauthClientId,
        string $oauthClientName,
        int $adminUserId,
        bool $allowWrites,
        ?array $toolNames = null,
        ?int $parentRefreshTokenId = null
    ): IssuedTokenPair {
        // Apply the operator-chosen re-authorization policy before any new row
        // hits the database. Refresh-token rotation (parentRefreshTokenId set)
        // is exempt — the rotator already revokes the predecessor, and applying
        // the policy here would also nuke the very token the refresh is
        // replacing, breaking long-lived MCP sessions.
        if ($parentRefreshTokenId === null) {
            $this->applyReauthPolicy($oauthClientId, $adminUserId);
        }

        $accessTtl = $this->config->getOAuthAccessTokenLifetime();
        $refreshTtlDays = $this->config->getOAuthRefreshTokenLifetimeDays();

        $accessPlain = $this->tokenGenerator->generate();
        $accessHash = $this->tokenHasher->hash($accessPlain);
        // UTC stamp to match Token::isExpired()'s UTC parsing regardless of server TZ.
        $accessExpiresAt = gmdate('Y-m-d H:i:s', time() + $accessTtl);

        $normalizedTools = ($toolNames === null || $toolNames === [])
            ? null
            : array_values($toolNames);

        // OAuth-protocol scope summary derived deterministically from the granted tool set so
        // the wire-level `scope` echo matches what's stored in `scopes_json`. CLI-issued
        // tokens (toolNames === null) never carry an OAuth scope.
        $grantedScope = $normalizedTools === null
            ? null
            : ($this->toolGrantResolver->summarizeScope($normalizedTools) ?: null);

        $token = $this->tokenFactory->create();
        $token->setAdminUserId($adminUserId);
        // Cap the client-name slice so 'OAuth: <name>' fits in magebit_mcp_token.name (varchar 128).
        $token->setName(sprintf('OAuth: %s', mb_substr($oauthClientName, 0, 121)));
        $token->setTokenHash($accessHash);
        $token->setAllowWrites($allowWrites);
        $token->setExpiresAt($accessExpiresAt);
        $token->setOAuthClientId($oauthClientId);
        $token->setScopes($normalizedTools);

        $this->tokenRepository->save($token);
        $accessTokenId = $token->getId();
        if ($accessTokenId === null) {
            throw new RuntimeException('Failed to persist OAuth access token row.');
        }

        $refreshPlain = $this->tokenGenerator->generate();
        $refreshHash = $this->tokenHasher->hash($refreshPlain);
        $refreshExpiresAt = gmdate('Y-m-d H:i:s', time() + ($refreshTtlDays * 86400));

        $refresh = $this->refreshTokenFactory->create();
        $refresh->setTokenHash($refreshHash);
        $refresh->setOAuthClientId($oauthClientId);
        $refresh->setAccessTokenId($accessTokenId);
        $refresh->setParentRefreshTokenId($parentRefreshTokenId);
        $refresh->setExpiresAt($refreshExpiresAt);

        $this->refreshTokenRepository->save($refresh);
        $refreshTokenId = $refresh->getId();
        if ($refreshTokenId === null) {
            throw new RuntimeException('Failed to persist OAuth refresh token row.');
        }

        return new IssuedTokenPair(
            accessToken: $accessPlain,
            accessTokenId: $accessTokenId,
            expiresIn: $accessTtl,
            refreshToken: $refreshPlain,
            refreshTokenId: $refreshTokenId,
            grantedScope: $grantedScope
        );
    }

    /**
     * Apply `magebit_mcp/oauth/reauth_behavior` to any prior active tokens for
     * the same (client, admin) pair.
     *
     * @param int $oauthClientId
     * @param int $adminUserId
     * @return void
     * @throws OAuthException When policy is REJECT and an active token exists.
     */
    private function applyReauthPolicy(int $oauthClientId, int $adminUserId): void
    {
        $behavior = $this->config->getOAuthReauthBehavior();
        if ($behavior === ReauthBehavior::ALLOW_MULTIPLE) {
            return;
        }

        $active = $this->tokenRepository->getActiveByClientAndAdmin($oauthClientId, $adminUserId);
        if ($active === []) {
            return;
        }

        if ($behavior === ReauthBehavior::REJECT) {
            throw new OAuthException(
                'invalid_grant',
                'An active token already exists for this client and admin. Revoke it before requesting a new one.'
            );
        }

        // ROTATE — revoke every active prior token. The downstream FK from
        // magebit_mcp_oauth_refresh_token uses onDelete=CASCADE on access_token_id,
        // and the rotator's reuse-detection covers refresh tokens whose access
        // token is now revoked, so we don't need to walk that table here.
        foreach ($active as $token) {
            $id = $token->getId();
            if ($id !== null) {
                $this->tokenRepository->revoke($id);
            }
        }
    }
}
