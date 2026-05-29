<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Model\Util;

class ToolDomain
{
    public const OTHER_KEY = '_other';

    /**
     * @param array<string, string> $labels Domain key → display label. Keys not
     *        present here fall back to ucfirst(); register entries here only for
     *        acronyms or other casings ucfirst gets wrong.
     */
    public function __construct(
        private readonly array $labels = []
    ) {
    }

    /**
     * First dotted segment of a machine name, or OTHER_KEY when it has none.
     *
     * @param string $name
     * @return string
     */
    public function keyFor(string $name): string
    {
        $dotIdx = strpos($name, '.');
        if ($dotIdx === false || $dotIdx === 0) {
            return self::OTHER_KEY;
        }
        return substr($name, 0, $dotIdx);
    }

    /**
     * Human label for a domain key (registered map first, ucfirst fallback).
     *
     * @param string $key
     * @return string
     */
    public function label(string $key): string
    {
        if ($key === self::OTHER_KEY) {
            return (string) __('Other');
        }
        return $this->labels[$key] ?? ucfirst($key);
    }

    /**
     * Prepend the domain label to a display title ("Domain: Title"), or return
     * the bare title when the name has no resolvable domain.
     *
     * @param string $name Machine name (dotted).
     * @param string $title Human title from getTitle().
     * @return string
     */
    public function prefixTitle(string $name, string $title): string
    {
        $key = $this->keyFor($name);
        if ($key === self::OTHER_KEY) {
            return $title;
        }
        return $this->label($key) . ': ' . $title;
    }
}
