<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Model\OAuth;

/**
 * Per-client mapping of OAuth consents to Magento admin users.
 *
 * - {@see self::PERSONAL} — every admin who reaches the consent screen
 *   approves on behalf of themselves. The issued token's admin_user_id is
 *   the authorizing admin. This is the historical default.
 * - {@see self::SHARED} — the client pins one Magento admin
 *   (`service_admin_user_id`); only that admin may approve consent and every
 *   issued token's admin_user_id is the pinned admin. Intended for
 *   organization-wide MCP connectors where many Claude seats hit a single
 *   pre-registered client.
 */
enum AuthMode: string
{
    case PERSONAL = 'personal';
    case SHARED = 'shared';

    /**
     * Tolerant parser used when reading the column from storage. Unknown /
     * legacy values fall back to PERSONAL so a botched manual UPDATE never
     * locks the consent flow.
     *
     * @param string|null $value
     * @return self
     */
    public static function fromStorage(?string $value): self
    {
        if ($value === null) {
            return self::PERSONAL;
        }
        return self::tryFrom($value) ?? self::PERSONAL;
    }

    /**
     * Operator-facing label rendered on the OAuth Clients grid + edit form.
     *
     * @return string
     */
    public function label(): string
    {
        return match ($this) {
            self::PERSONAL => 'Personal (each admin authorizes for themselves)',
            self::SHARED => 'Shared organization connector',
        };
    }
}
