<?php
declare(strict_types=1);

namespace DPXL\Shield\Firewall;

enum Decision: string {
    case PASS      = 'pass';
    case BLOCK     = 'block';
    case CHALLENGE = 'challenge';
    case LOG_ONLY  = 'log_only';
}
