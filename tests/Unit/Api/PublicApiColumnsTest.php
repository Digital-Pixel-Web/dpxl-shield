<?php
declare(strict_types=1);

namespace DPXL\Shield\Tests\Unit\Api;

use DPXL\Shield\Api\PublicApi;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

/**
 * The public API selects a hard-coded column list per endpoint. A name that does
 * not exist in the schema produces a SQL error at request time, not at boot —
 * so it would ship silently and only surface as a 500 on someone's SIEM poll.
 *
 * This test parses the real CREATE TABLE statements out of Database and asserts
 * every selected column exists, which is what an integration test against a live
 * database would tell us, without needing one.
 */
class PublicApiColumnsTest extends TestCase {

    /**
     * Column names per table, read from the schema definitions.
     *
     * @return array<string,string[]>
     */
    private function schemaColumns(): array {
        $reflection = new ReflectionMethod(\DPXL\Shield\Core\Database::class, 'getTableDefinitions');
        $reflection->setAccessible(true);

        /** @var string[] $statements */
        $statements = $reflection->invoke(null, 'wp_', '');

        $tables = [];

        foreach ($statements as $sql) {
            if (!preg_match('/CREATE TABLE\s+(\S+)\s*\((.*)\)\s*;/s', $sql, $match)) {
                continue;
            }

            $columns = [];

            foreach (explode("\n", $match[2]) as $line) {
                $line = trim($line);

                // Skip key/index declarations — only column definitions matter.
                if ($line === '' || preg_match('/^(PRIMARY|UNIQUE|INDEX|KEY|FOREIGN|CONSTRAINT)\b/i', $line)) {
                    continue;
                }

                if (preg_match('/^`?([a-z_][a-z0-9_]*)`?\s+/i', $line, $col)) {
                    $columns[] = $col[1];
                }
            }

            $tables[$match[1]] = $columns;
        }

        return $tables;
    }

    /**
     * The column list each endpoint passes to collection().
     *
     * @return array<string,array{table:string,columns:string[]}>
     */
    private function endpointColumns(): array {
        $source = (string) file_get_contents(
            (new ReflectionClass(PublicApi::class))->getFileName()
        );

        $endpoints = [];

        // Each getter names its table then hands collection() a literal array.
        preg_match_all(
            '/\$table\s*=\s*\$wpdb->prefix\s*\.\s*\'([a-z_]+)\';(.*?)\$this->collection\(.*?\[(.*?)\]\s*\);/s',
            $source,
            $matches,
            PREG_SET_ORDER
        );

        foreach ($matches as $match) {
            preg_match_all("/'([a-z_]+)'/", $match[3], $cols);

            $endpoints[$match[1]] = [
                'table'   => $match[1],
                'columns' => $cols[1],
            ];
        }

        return $endpoints;
    }

    public function testTheParserActuallyFoundTheEndpoints(): void {
        $endpoints = $this->endpointColumns();

        // Guards the test itself: a silently empty match set would make every
        // assertion below pass without checking anything.
        $this->assertNotEmpty($endpoints, 'no endpoint column lists were parsed');
        $this->assertArrayHasKey('dpxl_shield_audit_log', $endpoints);
        $this->assertArrayHasKey('dpxl_shield_traffic_log', $endpoints);
        $this->assertArrayHasKey('dpxl_shield_scan_results', $endpoints);
    }

    public function testEverySelectedColumnExistsInTheSchema(): void {
        $schema = $this->schemaColumns();

        foreach ($this->endpointColumns() as $table => $endpoint) {
            $key = 'wp_' . $table;

            $this->assertArrayHasKey($key, $schema, "unknown table {$table}");

            foreach ($endpoint['columns'] as $column) {
                $this->assertContains(
                    $column,
                    $schema[$key],
                    "{$table}.{$column} is selected by the API but does not exist in the schema"
                );
            }
        }
    }

    /** Cursor pagination depends on an `id` column in every exposed table. */
    public function testEveryExposedTableIsPaginableById(): void {
        $schema = $this->schemaColumns();

        foreach ($this->endpointColumns() as $table => $endpoint) {
            $this->assertContains('id', $schema['wp_' . $table], "{$table} has no id to paginate on");
            $this->assertContains('id', $endpoint['columns'], "{$table} must return id so the client can build a cursor");
        }
    }
}
