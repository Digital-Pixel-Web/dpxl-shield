<?php
declare(strict_types=1);

namespace DPXL\Shield\Integrations;

/**
 * One configured outbound webhook destination.
 *
 * Endpoints are stored as plain arrays in the `webhook_endpoints` option; this
 * class is the boundary that turns untrusted stored data into something the
 * dispatcher can rely on. Anything that fails validation is rejected here
 * rather than blowing up mid-delivery.
 */
final class WebhookEndpoint {

    /** How the payload is shaped for the receiving service. */
    public const FORMAT_GENERIC   = 'generic';
    public const FORMAT_SLACK     = 'slack';
    public const FORMAT_DISCORD   = 'discord';
    public const FORMAT_PAGERDUTY = 'pagerduty';

    /** @var string */
    private $id;

    /** @var string */
    private $label;

    /** @var string */
    private $url;

    /** @var string */
    private $format;

    /** @var string */
    private $minLevel;

    /** @var string Shared secret for the HMAC signature. Empty = unsigned. */
    private $secret;

    /** @var bool */
    private $enabled;

    private function __construct(
        string $id,
        string $label,
        string $url,
        string $format,
        string $minLevel,
        string $secret,
        bool $enabled
    ) {
        $this->id       = $id;
        $this->label    = $label;
        $this->url      = $url;
        $this->format   = $format;
        $this->minLevel = $minLevel;
        $this->secret   = $secret;
        $this->enabled  = $enabled;
    }

    /** @return string[] */
    public static function formats(): array {
        return [self::FORMAT_GENERIC, self::FORMAT_SLACK, self::FORMAT_DISCORD, self::FORMAT_PAGERDUTY];
    }

    /**
     * Builds an endpoint from stored/submitted data.
     *
     * @param  array<string,mixed> $data
     * @return self|null Null when the data cannot produce a usable endpoint.
     */
    public static function fromArray(array $data): ?self {
        $url = isset($data['url']) ? trim((string) $data['url']) : '';

        // An endpoint without a valid HTTPS URL is not deliverable. Plain HTTP is
        // refused outright: these payloads describe security events on the site,
        // and sending them in the clear would leak exactly what an attacker wants.
        if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL) || stripos($url, 'https://') !== 0) {
            return null;
        }

        $format = isset($data['format']) ? (string) $data['format'] : self::FORMAT_GENERIC;

        if (!in_array($format, self::formats(), true)) {
            $format = self::FORMAT_GENERIC;
        }

        $minLevel = isset($data['min_level']) ? (string) $data['min_level'] : Severity::MEDIUM;

        if (!Severity::isValid($minLevel)) {
            $minLevel = Severity::MEDIUM;
        }

        $id = isset($data['id']) ? preg_replace('/[^a-z0-9_-]/i', '', (string) $data['id']) : '';

        if (!is_string($id) || $id === '') {
            $id = substr(hash('sha256', $url . '|' . $format), 0, 12);
        }

        $label = isset($data['label']) ? trim((string) $data['label']) : '';

        if ($label === '') {
            $host  = parse_url($url, PHP_URL_HOST);
            $label = is_string($host) && $host !== '' ? $host : $format;
        }

        return new self(
            $id,
            mb_substr($label, 0, 60),
            $url,
            $format,
            $minLevel,
            isset($data['secret']) ? (string) $data['secret'] : '',
            !isset($data['enabled']) || (bool) $data['enabled']
        );
    }

    public function id(): string {
        return $this->id;
    }

    public function label(): string {
        return $this->label;
    }

    public function url(): string {
        return $this->url;
    }

    public function format(): string {
        return $this->format;
    }

    public function minLevel(): string {
        return $this->minLevel;
    }

    public function secret(): string {
        return $this->secret;
    }

    public function isEnabled(): bool {
        return $this->enabled;
    }

    /** Should an alert at this severity be delivered here? */
    public function accepts(string $level): bool {
        return $this->enabled && Severity::atLeast($level, $this->minLevel);
    }

    /**
     * Storage form.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array {
        return [
            'id'        => $this->id,
            'label'     => $this->label,
            'url'       => $this->url,
            'format'    => $this->format,
            'min_level' => $this->minLevel,
            'secret'    => $this->secret,
            'enabled'   => $this->enabled,
        ];
    }

    /**
     * Storage form with the secret masked — for anything that leaves the server.
     *
     * The URL is included as-is on purpose: for Slack and Discord the URL *is*
     * the credential, so callers must treat this as privileged data and only
     * hand it to an administrator.
     *
     * @return array<string,mixed>
     */
    public function toPublicArray(): array {
        $data = $this->toArray();

        $data['secret']     = '';
        $data['has_secret'] = $this->secret !== '';

        return $data;
    }
}
