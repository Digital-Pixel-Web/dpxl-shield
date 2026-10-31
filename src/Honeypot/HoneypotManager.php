<?php
declare(strict_types=1);

namespace DPXL\Shield\Honeypot;

use DPXL\Shield\Core\Options;

/**
 * Honeypot module entry point.
 * Instantiates and registers both sub-modules.
 */
class HoneypotManager {

    private FormHoneypot   $formHoneypot;
    private DecoyEndpoints $decoyEndpoints;

    public function __construct() {
        $this->formHoneypot   = new FormHoneypot();
        $this->decoyEndpoints = new DecoyEndpoints();
    }

    public function registerHooks(): void {
        if (!Options::get('honeypot_enabled', true)) {
            return;
        }

        $this->formHoneypot->registerHooks();
        $this->decoyEndpoints->registerHooks();
    }
}
