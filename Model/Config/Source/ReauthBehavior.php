<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

/**
 * Storefront-config picker for `magebit_mcp/oauth/reauth_behavior` — controls
 * what happens when the same (oauth_client_id, admin_user_id) pair receives a
 * fresh authorization while a prior token is still live.
 *
 * Values are consumed by {@see \Magebit\Mcp\Model\OAuth\AccessTokenIssuer}.
 */
class ReauthBehavior implements OptionSourceInterface
{
    public const ALLOW_MULTIPLE = 'allow_multiple';
    public const ROTATE = 'rotate';
    public const REJECT = 'reject';

    /**
     * @return array<int, array{value: string, label: string}>
     */
    public function toOptionArray(): array
    {
        return [
            [
                'value' => self::ALLOW_MULTIPLE,
                'label' => __('Allow multiple — keep prior token, issue a new one alongside')->render(),
            ],
            [
                'value' => self::ROTATE,
                'label' => __('Rotate — revoke prior token(s) for this client + admin, then issue')->render(),
            ],
            [
                'value' => self::REJECT,
                'label' => __('Reject — fail the grant when an active token already exists')->render(),
            ],
        ];
    }

    /**
     * Strict parser: returns one of the three known values, falling back to
     * ALLOW_MULTIPLE (the historical behavior) on null / unknown input so a
     * misconfigured row never locks the OAuth flow.
     *
     * @param mixed $value
     * @return string
     */
    public static function normalize(mixed $value): string
    {
        if (!is_string($value)) {
            return self::ALLOW_MULTIPLE;
        }
        return match ($value) {
            self::ROTATE => self::ROTATE,
            self::REJECT => self::REJECT,
            default => self::ALLOW_MULTIPLE,
        };
    }
}
