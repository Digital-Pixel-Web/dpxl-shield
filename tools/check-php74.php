<?php
/**
 * Static check: does the plugin's own source stay within PHP 7.4 syntax?
 *
 * The plugin targets shared hosting where PHP 7.4 is still common, but the dev
 * machine runs PHP 8.x — so `php -l` here proves nothing. PHPCompatibility is
 * no help either: its stable release predates PHP 8 and reports a clean bill of
 * health on a file full of enums and match expressions.
 *
 * So we walk the AST ourselves with nikic/php-parser (already vendored) and
 * flag every construct that would be a parse error on 7.4. This catches syntax,
 * not behaviour — see the function-level checks at the bottom for the handful of
 * PHP 8 standard-library calls that would fatal at runtime instead.
 *
 * Usage:  php tools/check-php74.php [path ...]     (defaults to the plugin source)
 * Exit:   0 clean, 1 violations found, 2 could not run
 */
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

/**
 * PHP 8.0+ functions that parse fine on 7.4 but fatal when called.
 *
 * The three string helpers are shipped as polyfills in src/Compat/php-polyfill.php,
 * which both entry points require before anything else — so calls to them are
 * safe and are only reported when that file goes missing.
 */
const PHP8_FUNCTIONS = [
    'array_is_list'  => '8.1',
    'enum_exists'    => '8.1',
    'fdiv'           => '8.0',
    'get_debug_type' => '8.0',
];

/** Covered by src/Compat/php-polyfill.php. */
const POLYFILLED_FUNCTIONS = [
    'str_contains'    => '8.0',
    'str_starts_with' => '8.0',
    'str_ends_with'   => '8.0',
];

const POLYFILL_FILE = __DIR__ . '/../src/Compat/php-polyfill.php';

final class Php74Visitor extends NodeVisitorAbstract {

    /** @var array<int,array{line:int,version:string,what:string}> */
    public array $findings = [];

    private string $source;

    public function __construct(string $source) {
        $this->source = $source;
    }

    private function flag(Node $node, string $version, string $what): void {
        $this->findings[] = ['line' => $node->getLine(), 'version' => $version, 'what' => $what];
    }

    /**
     * A trailing comma in a *parameter list* is 8.0; in an argument list it has
     * been legal since 7.3. Only the AST can tell them apart, so we look at the
     * raw source between the last parameter and its closing paren.
     */
    private function checkTrailingComma(Node $node, array $params): void {
        if ($params === []) {
            return;
        }

        $last = end($params);
        $from = $last->getAttribute('endFilePos');

        if (!is_int($from)) {
            return;
        }

        $tail = substr($this->source, $from + 1);
        $tail = preg_replace('~/\*.*?\*/~s', '', $tail) ?? $tail;

        if (preg_match('~^\s*,\s*\)~', $tail)) {
            $this->flag($node, '8.0', 'trailing comma in parameter list');
        }
    }

    public function enterNode(Node $node) {
        if ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            $this->checkTrailingComma($node, $node->params);
        }

        // ── PHP 8.0 ──────────────────────────────────────────────────────────
        if ($node instanceof Node\Expr\Match_) {
            $this->flag($node, '8.0', 'match expression — use switch or if/else');
        }

        if ($node instanceof Node\Expr\NullsafePropertyFetch || $node instanceof Node\Expr\NullsafeMethodCall) {
            $this->flag($node, '8.0', 'nullsafe operator ?->');
        }

        if ($node instanceof Node\Expr\Throw_) {
            $this->flag($node, '8.0', 'throw as an expression');
        }

        if ($node instanceof Node\Arg && $node->name !== null) {
            $this->flag($node, '8.0', 'named argument');
        }

        if ($node instanceof Node\Param) {
            // Constructor property promotion: a parameter carrying visibility.
            if ($node->flags !== 0) {
                $this->flag($node, '8.0', 'promoted constructor property — declare the property explicitly');
            }

            if ($node->variadic === false && $node->default === null && $node->type === null) {
                // nothing to check
            }
        }

        if ($node instanceof Node\AttributeGroup) {
            $this->flag($node, '8.0', 'attribute #[...]');
        }

        if ($node instanceof Node\Stmt\Catch_ && $node->var === null) {
            $this->flag($node, '8.0', 'non-capturing catch');
        }

        // ── PHP 8.1 ──────────────────────────────────────────────────────────
        if ($node instanceof Node\Stmt\Enum_) {
            $this->flag($node, '8.1', 'enum — use a class with constants');
        }

        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Expr) {
            // first-class callable syntax: foo(...)
            foreach ($node->args as $arg) {
                if ($arg instanceof Node\VariadicPlaceholder) {
                    $this->flag($node, '8.1', 'first-class callable syntax foo(...)');
                }
            }
        }

        if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            foreach ($node->args as $arg) {
                if ($arg instanceof Node\VariadicPlaceholder) {
                    $this->flag($node, '8.1', 'first-class callable syntax');
                }
            }
        }

        // readonly properties / promoted readonly params
        if ($node instanceof Node\Stmt\Property && ($node->flags & Node\Stmt\Class_::MODIFIER_READONLY)) {
            $this->flag($node, '8.1', 'readonly property');
        }

        if ($node instanceof Node\Param && ($node->flags & Node\Stmt\Class_::MODIFIER_READONLY)) {
            $this->flag($node, '8.1', 'readonly promoted property');
        }

        if ($node instanceof Node\Stmt\ClassConst && ($node->flags & Node\Stmt\Class_::MODIFIER_FINAL)) {
            $this->flag($node, '8.1', 'final class constant');
        }

        // ── Types ────────────────────────────────────────────────────────────
        foreach ($this->typesOf($node) as $type) {
            if ($type instanceof Node\UnionType) {
                $this->flag($node, '8.0', 'union type');
            }

            if ($type instanceof Node\IntersectionType) {
                $this->flag($node, '8.1', 'intersection type');
            }

            if ($type instanceof Node\Identifier) {
                $name = strtolower($type->name);

                if ($name === 'mixed') {
                    $this->flag($node, '8.0', 'mixed type');
                }

                if ($name === 'static') {
                    $this->flag($node, '8.0', 'static return type');
                }

                if ($name === 'never') {
                    $this->flag($node, '8.1', 'never return type');
                }
            }
        }

        // ── PHP 8 standard library ───────────────────────────────────────────
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $fn = strtolower($node->name->toString());

            if (isset(PHP8_FUNCTIONS[$fn])) {
                $this->flag($node, PHP8_FUNCTIONS[$fn], "{$fn}() — needs a polyfill on 7.4");
            }

            if (isset(POLYFILLED_FUNCTIONS[$fn]) && !is_file(POLYFILL_FILE)) {
                $this->flag($node, POLYFILLED_FUNCTIONS[$fn], "{$fn}() — polyfill file is missing");
            }
        }

        return null;
    }

    /** @return list<Node|null> */
    private function typesOf(Node $node): array {
        $types = [];

        if ($node instanceof Node\Param || $node instanceof Node\Stmt\Property) {
            $types[] = $node->type;
        }

        if ($node instanceof Node\Stmt\ClassMethod || $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Expr\Closure || $node instanceof Node\Expr\ArrowFunction) {
            $types[] = $node->returnType;

            foreach ($node->params as $param) {
                $types[] = $param->type;
            }
        }

        return array_filter($types);
    }
}

// ── Collect targets ──────────────────────────────────────────────────────────

$roots = array_slice($argv, 1);

if ($roots === []) {
    $base  = dirname(__DIR__);
    $roots = [
        $base . '/src',
        $base . '/dpxl-shield.php',
        $base . '/dpxl-shield-waf.php',
        $base . '/uninstall.php',
    ];
}

$files = [];

foreach ($roots as $root) {
    if (is_file($root)) {
        $files[] = $root;
        continue;
    }

    if (!is_dir($root)) {
        fwrite(STDERR, "skip: {$root} not found\n");
        continue;
    }

    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));

    foreach ($it as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $files[] = $file->getPathname();
        }
    }
}

sort($files);

// ── Scan ─────────────────────────────────────────────────────────────────────

$parser = (new ParserFactory())->createForNewestSupportedVersion();
$base   = dirname(__DIR__) . '/';
$total  = 0;

foreach ($files as $file) {
    $source = (string) file_get_contents($file);

    try {
        $ast = $parser->parse($source);
    } catch (Throwable $e) {
        fwrite(STDERR, "parse error in {$file}: {$e->getMessage()}\n");
        exit(2);
    }

    if ($ast === null) {
        continue;
    }

    $visitor   = new Php74Visitor($source);
    $traverser = new NodeTraverser();
    $traverser->addVisitor($visitor);
    $traverser->traverse($ast);

    if ($visitor->findings === []) {
        continue;
    }

    $relative = str_replace($base, '', $file);

    foreach ($visitor->findings as $f) {
        printf("%s:%d  [PHP %s]  %s\n", $relative, $f['line'], $f['version'], $f['what']);
        $total++;
    }
}

if ($total > 0) {
    printf("\n%d construct(s) above the PHP 7.4 floor.\n", $total);
    exit(1);
}

echo "Clean: source stays within PHP 7.4.\n";
exit(0);
