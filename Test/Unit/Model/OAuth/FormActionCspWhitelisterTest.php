<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Test\Unit\Model\OAuth;

use Magebit\Mcp\Model\OAuth\FormActionCspWhitelister;
use Magento\Csp\Model\Collector\DynamicCollector;
use Magento\Csp\Model\Policy\FetchPolicy;
use Magento\Csp\Model\Policy\FetchPolicyFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class FormActionCspWhitelisterTest extends TestCase
{
    private DynamicCollector&MockObject $collector;
    private FetchPolicyFactory&MockObject $policyFactory;
    private FormActionCspWhitelister $whitelister;

    protected function setUp(): void
    {
        $this->collector = $this->createMock(DynamicCollector::class);
        $this->policyFactory = $this->createMock(FetchPolicyFactory::class);
        // Build a real FetchPolicy from the requested args so assertions exercise the real DTO.
        $this->policyFactory->method('create')->willReturnCallback(
            static fn (array $data): FetchPolicy => new FetchPolicy(
                (string) $data['id'],
                (bool) ($data['noneAllowed'] ?? true),
                (array) ($data['hostSources'] ?? []),
                (array) ($data['schemeSources'] ?? []),
                (bool) ($data['selfAllowed'] ?? false)
            )
        );
        $this->whitelister = new FormActionCspWhitelister($this->collector, $this->policyFactory);
    }

    public function testWhitelistsRedirectOriginForFormAction(): void
    {
        $this->collector->expects(self::once())->method('add')->with(
            self::callback(static function (FetchPolicy $policy): bool {
                return $policy->getId() === 'form-action'
                    && $policy->isSelfAllowed() === true
                    && $policy->getHostSources() === ['https://claude.ai'];
            })
        );

        $this->whitelister->whitelistRedirectTarget('https://claude.ai/api/mcp/auth_callback');
    }

    public function testIncludesNonDefaultPortInOrigin(): void
    {
        $this->collector->expects(self::once())->method('add')->with(
            self::callback(
                static fn (FetchPolicy $policy): bool => $policy->getHostSources() === ['http://localhost:33418']
            )
        );

        $this->whitelister->whitelistRedirectTarget('http://localhost:33418/oauth/callback');
    }

    public function testIgnoresEmptyRedirectUri(): void
    {
        $this->collector->expects(self::never())->method('add');
        $this->whitelister->whitelistRedirectTarget('');
    }

    public function testIgnoresRedirectUriWithoutHost(): void
    {
        $this->collector->expects(self::never())->method('add');
        $this->whitelister->whitelistRedirectTarget('/relative/path');
    }
}
