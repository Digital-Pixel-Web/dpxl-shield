<?php
declare(strict_types=1);

namespace DPXL\Shield\Scanner;

// Direct access guard. The pre-WordPress firewall loads some of these classes
// before ABSPATH exists, so its own marker is accepted too.
defined('ABSPATH') || defined('DPXL_SHIELD_EXTENDED_ACTIVE') || exit;

/**
 * Scans WordPress post content for injected malicious links/iframes/scripts.
 *
 * The original MVP was too aggressive and treated ordinary editorial links as
 * security issues. This version only reports clear or reasonably suspicious
 * content-injection patterns, and normal external links are ignored.
 */
class ContentSafetyChecker {

    /** TLD / domain patterns often abused in spam campaigns. These are LOW severity by default. */
    private const SUSPECT_TLDS = [
        '\\.tk$', '\\.ml$', '\\.ga$', '\\.cf$', '\\.gq$',
        '\\.loan$', '\\.click$', '\\.top$',
    ];

    /** Widely used embed/script hosts that should not create noise. */
    private const ALLOWED_EXTERNAL_HOST_PARTS = [
        'youtube.com', 'youtu.be', 'vimeo.com', 'player.vimeo.com',
        'google.com', 'googleapis.com', 'gstatic.com', 'googletagmanager.com', 'google-analytics.com',
        'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
        'cloudflare.com', 'cdnjs.cloudflare.com', 'jsdelivr.net', 'unpkg.com',
        'wordpress.com', 'wp.com', 'gravatar.com',
    ];

    /** Scan all published posts and pages. */
    public function scanAllContent(): \Generator {
        $paged = 1;

        do {
            $query = new \WP_Query([
                'post_type'      => ['post', 'page'],
                'post_status'    => 'publish',
                'posts_per_page' => 50,
                'paged'          => $paged,
                'fields'         => 'ids',
            ]);

            if (!$query->have_posts()) {
                break;
            }

            foreach ($query->posts as $postId) {
                $result = $this->checkPost((int) $postId);

                if ($result !== null) {
                    yield $result;
                }
            }

            $paged++;
        } while ($paged <= $query->max_num_pages);
    }

    /**
     * Check a single post.
     *
     * @return array{file_path:string, issue_type:string, severity:string, details:string}|null
     */
    public function checkPost(int $postId): ?array {
        $post = get_post($postId);

        if (!$post) {
            return null;
        }

        $content = (string) $post->post_content;
        $issues  = [];

        $issues = array_merge($issues, $this->detectIframes($content));
        $issues = array_merge($issues, $this->detectExternalScripts($content));
        $issues = array_merge($issues, $this->detectHiddenLinks($content));
        $issues = array_merge($issues, $this->detectSuspectLinks($content));

        if (empty($issues)) {
            return null;
        }

        $severities = array_column($issues, 'severity');
        $severity   = in_array('high', $severities, true) ? 'high' : (in_array('medium', $severities, true) ? 'medium' : 'low');

        return [
            'file_path'  => "post:{$postId}:{$post->post_title}",
            'issue_type' => 'unknown',
            'severity'   => $severity,
            'details'    => implode('; ', array_column($issues, 'detail')),
        ];
    }

    // ── Detectors ──────────────────────────────────────────────────────────

    /** @return array<int,array{severity:string,detail:string}> */
    private function detectIframes(string $content): array {
        $issues = [];
        preg_match_all('/<iframe[^>]+src=["\']?([^"\'>\s]+)/i', $content, $matches);

        foreach ($matches[1] as $src) {
            $src = html_entity_decode((string) $src, ENT_QUOTES | ENT_HTML5);

            if (preg_match('/^(?:data|javascript):/i', $src)) {
                $issues[] = ['severity' => 'high', 'detail' => 'Protocolo de iframe perigoso detectado: ' . substr($src, 0, 120)];
                continue;
            }

            if ($this->isInternalUrl($src) || $this->isAllowedExternalHost($src)) {
                continue;
            }

            // External iframes can be legitimate; keep as medium review item, not critical.
            $issues[] = ['severity' => 'medium', 'detail' => 'Iframe externo precisa de revisão: ' . substr($src, 0, 120)];
        }

        return $issues;
    }

    /** @return array<int,array{severity:string,detail:string}> */
    private function detectExternalScripts(string $content): array {
        $issues = [];
        preg_match_all('/<script[^>]+src=["\']?([^"\'>\s]+)/i', $content, $matches);

        foreach ($matches[1] as $src) {
            $src = html_entity_decode((string) $src, ENT_QUOTES | ENT_HTML5);

            if ($this->isInternalUrl($src) || $this->isAllowedExternalHost($src)) {
                continue;
            }

            $issues[] = ['severity' => 'medium', 'detail' => 'Script externo precisa de revisão: ' . substr($src, 0, 120)];
        }

        // Inline obfuscation is more relevant than a normal external URL.
        $obfuscation = [
            '/eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)/i',
            '/document\.write\s*\(\s*(?:unescape|atob)/i',
            '/(?:fromCharCode|atob)\s*\([^)]{80,}\)/i',
        ];

        foreach ($obfuscation as $pattern) {
            if (@preg_match($pattern, $content) === 1) {
                $issues[] = ['severity' => 'high', 'detail' => 'Script embutido ofuscado detectado no conteúdo do post.'];
                break;
            }
        }

        return $issues;
    }

    /** @return array<int,array{severity:string,detail:string}> */
    private function detectHiddenLinks(string $content): array {
        $issues = [];

        // Hidden external links are a common SEO spam pattern.
        preg_match_all('/<a[^>]+href=["\']([^"\'>\s]+)[^>]*style=["\']([^"\']*)["\'][^>]*>/i', $content, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $href  = html_entity_decode((string) ($match[1] ?? ''), ENT_QUOTES | ENT_HTML5);
            $style = strtolower((string) ($match[2] ?? ''));

            if ($this->isInternalUrl($href)) {
                continue;
            }

            if (preg_match('/(?:display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0|visibility\s*:\s*hidden|color\s*:\s*transparent)/i', $style)) {
                $issues[] = ['severity' => 'high', 'detail' => 'Link externo escondido detectado: ' . substr($href, 0, 120)];
            }
        }

        return $issues;
    }

    /** @return array<int,array{severity:string,detail:string}> */
    private function detectSuspectLinks(string $content): array {
        $issues = [];
        preg_match_all('/<a[^>]+href=["\']([^"\'>\s]+)/i', $content, $matches);

        foreach ($matches[1] as $href) {
            $href = html_entity_decode((string) $href, ENT_QUOTES | ENT_HTML5);

            if ($this->isInternalUrl($href) || $this->isAllowedExternalHost($href)) {
                continue;
            }

            $host = strtolower((string) (parse_url($href, PHP_URL_HOST) ?? ''));

            if ($host === '') {
                continue;
            }

            foreach (self::SUSPECT_TLDS as $tld) {
                if (@preg_match('/' . $tld . '/i', $host) === 1) {
                    $issues[] = ['severity' => 'low', 'detail' => 'O link externo usa um domínio de topo frequentemente abusado e merece revisão: ' . esc_html($href)];
                    break;
                }
            }
        }

        return $issues;
    }

    private function isInternalUrl(string $url): bool {
        $siteHost = strtolower((string) (parse_url(get_option('siteurl'), PHP_URL_HOST) ?? ''));
        $host     = strtolower((string) (parse_url($url, PHP_URL_HOST) ?? ''));

        if ($host === '') {
            return true;
        }

        return $siteHost !== '' && ($host === $siteHost || str_ends_with($host, '.' . $siteHost));
    }

    private function isAllowedExternalHost(string $url): bool {
        $host = strtolower((string) (parse_url($url, PHP_URL_HOST) ?? ''));

        if ($host === '') {
            return true;
        }

        foreach (self::ALLOWED_EXTERNAL_HOST_PARTS as $allowed) {
            if ($host === $allowed || str_ends_with($host, '.' . $allowed)) {
                return true;
            }
        }

        return false;
    }
}
