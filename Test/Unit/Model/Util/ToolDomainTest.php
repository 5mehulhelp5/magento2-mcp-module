<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Test\Unit\Model\Util;

use Magebit\Mcp\Model\Util\ToolDomain;
use PHPUnit\Framework\TestCase;

class ToolDomainTest extends TestCase
{
    /**
     * @param array<string, string> $labels
     * @return ToolDomain
     */
    private function makeToolDomain(array $labels = ['system' => 'System', 'cms' => 'CMS']): ToolDomain
    {
        return new ToolDomain($labels);
    }

    public function testKeyForReturnsFirstDottedSegment(): void
    {
        $domain = $this->makeToolDomain();
        self::assertSame('system', $domain->keyFor('system.cache.clean'));
        self::assertSame('reports', $domain->keyFor('reports.sales.orders'));
    }

    public function testKeyForFallsBackToOtherWhenNoDot(): void
    {
        $domain = $this->makeToolDomain();
        self::assertSame(ToolDomain::OTHER_KEY, $domain->keyFor('noseparator'));
        self::assertSame(ToolDomain::OTHER_KEY, $domain->keyFor('.leadingdot'));
    }

    public function testLabelUsesRegisteredMapThenUcfirstFallback(): void
    {
        $domain = $this->makeToolDomain();
        self::assertSame('CMS', $domain->label('cms'));
        self::assertSame('System', $domain->label('system'));
        // Unregistered domain falls back to ucfirst().
        self::assertSame('Inventory', $domain->label('inventory'));
    }

    public function testLabelIsExtensibleViaInjectedMap(): void
    {
        // A third-party module registers its own domain label via di.xml; the
        // map override is all it takes for the prefix + grouping to pick it up.
        $domain = $this->makeToolDomain(['inventory' => 'Inventory (MSI)']);
        self::assertSame('Inventory (MSI)', $domain->label('inventory'));
    }

    public function testPrefixTitlePrependsDomainLabel(): void
    {
        $domain = $this->makeToolDomain();
        self::assertSame('System: Clean Cache', $domain->prefixTitle('system.cache.clean', 'Clean Cache'));
        self::assertSame('CMS: Get Page', $domain->prefixTitle('cms.page.get', 'Get Page'));
    }

    public function testPrefixTitleReturnsBareTitleWhenNoDomain(): void
    {
        $domain = $this->makeToolDomain();
        self::assertSame('Bare Title', $domain->prefixTitle('noseparator', 'Bare Title'));
    }
}
