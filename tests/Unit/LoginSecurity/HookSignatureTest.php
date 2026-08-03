<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\LoginSecurity;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionNamedType;

/**
 * Hook callbacks must accept what WordPress actually passes.
 *
 * Every file here declares strict_types, so a type hint that disagrees with the
 * hook's real signature is not a warning — it is an uncaught TypeError that
 * takes the whole page down. That is exactly what happened with
 * `user_profile_update_errors`: the callback declared WP_User, WordPress passes
 * a bare stdClass, and every password change from the profile screen died.
 *
 * These assertions are deliberately about the *signature*, not the behaviour —
 * they are what a unit suite can check without a WordPress runtime.
 */
class HookSignatureTest extends TestCase {

    private function parameter(string $class, string $method, int $index): \ReflectionParameter {
        $parameters = (new ReflectionMethod($class, $method))->getParameters();

        $this->assertArrayHasKey($index, $parameters, "{$class}::{$method} has no parameter #{$index}");

        return $parameters[$index];
    }

    private function typeName(\ReflectionParameter $parameter): ?string {
        $type = $parameter->getType();

        return $type instanceof ReflectionNamedType ? $type->getName() : null;
    }

    // ── user_profile_update_errors ───────────────────────────────────────────

    /**
     * WordPress documents the third argument as stdClass and passes exactly
     * that — a partially assembled object from edit_user(), never a WP_User.
     */
    public function testProfileUpdateDoesNotDemandAWpUser(): void {
        $parameter = $this->parameter(
            \DPXL\Shield\LoginSecurity\PasswordAudit::class,
            'onProfileUpdate',
            2
        );

        $this->assertNotSame(
            'WP_User',
            $this->typeName($parameter),
            'user_profile_update_errors passes a stdClass; demanding WP_User is a fatal TypeError.'
        );
    }

    /**
     * On user *creation* the object carries neither ID nor user_login, so the
     * callback must not assume either exists.
     */
    public function testProfileUpdateSurvivesAnObjectWithoutIdOrLogin(): void {
        $audit  = new \DPXL\Shield\LoginSecurity\PasswordAudit();
        $errors = new \WP_Error();

        // No pass1 in POST → the callback returns before any HIBP lookup, which
        // keeps this a pure signature/guard test with no network involved.
        $_POST = [];

        $result = $audit->onProfileUpdate($errors, false, new \stdClass());

        $this->assertSame($errors, $result);
    }

    // ── wp_login_failed ──────────────────────────────────────────────────────

    /**
     * Core passes ($username, $error), but WooCommerce and hand-rolled login
     * forms still fire this action with the username alone. A required second
     * parameter would make that an ArgumentCountError — a fatal on the login
     * page, in exchange for nothing.
     *
     * @return array<string,array{0:string,1:string}>
     */
    public static function loginFailedCallbacks(): array {
        return [
            'brute force' => [\DPXL\Shield\LoginSecurity\BruteForceProtection::class, 'onLoginFailed'],
            'login audit' => [\DPXL\Shield\LoginSecurity\LoginAudit::class, 'onLoginFailure'],
        ];
    }

    /**
     * @dataProvider loginFailedCallbacks
     */
    public function testLoginFailedCallbacksTolerateAMissingErrorArgument(string $class, string $method): void {
        $parameter = $this->parameter($class, $method, 1);

        $this->assertTrue(
            $parameter->isOptional(),
            "{$class}::{$method}() must tolerate being called with the username alone."
        );
    }

    /**
     * @dataProvider loginFailedCallbacks
     */
    public function testLoginFailedCallbacksDoNotDemandAWpError(string $class, string $method): void {
        $this->assertNotSame('WP_Error', $this->typeName($this->parameter($class, $method, 1)));
    }
}
