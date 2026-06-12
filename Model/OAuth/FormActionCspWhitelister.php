<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Model\OAuth;

use Magento\Csp\Model\Collector\DynamicCollector;
use Magento\Csp\Model\Policy\FetchPolicyFactory;

class FormActionCspWhitelister
{
    /**
     * @param DynamicCollector $dynamicCollector
     * @param FetchPolicyFactory $fetchPolicyFactory
     */
    public function __construct(
        private readonly DynamicCollector $dynamicCollector,
        private readonly FetchPolicyFactory $fetchPolicyFactory
    ) {
    }

    /**
     * @param string $redirectUri
     * @return void
     */
    public function whitelistRedirectTarget(string $redirectUri): void
    {
        $origin = $this->originOf($redirectUri);
        if ($origin === null) {
            return;
        }

        // selfAllowed is OR-merged into the existing form-action policy, so it stays
        // safe to set even when this is the only contributor to the directive.
        $this->dynamicCollector->add(
            $this->fetchPolicyFactory->create([
                'id' => 'form-action',
                'noneAllowed' => false,
                'hostSources' => [$origin],
                'selfAllowed' => true,
            ])
        );
    }

    /**
     * @param string $redirectUri
     * @return string|null A `scheme://host[:port]` origin, or null when unparseable.
     */
    private function originOf(string $redirectUri): ?string
    {
        // phpcs:ignore Magento2.Functions.DiscouragedFunction
        $parts = parse_url($redirectUri);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }

        $origin = $parts['scheme'] . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }
        return $origin;
    }
}
