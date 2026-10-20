<?php

declare(strict_types=1);

use OpenBackAppAuthJoomla\Integration\GroupMapper;
use PHPUnit\Framework\TestCase;

final class GroupMapperTest extends TestCase
{
    public function testRulesFromTheSubformValue(): void
    {
        // As Joomla stores a repeatable subform: an object of rows keyed group_map0, group_map1...
        $stored = json_decode('{"group_map0":{"role":"admin","group":"6"},"group_map1":{"role":" member ","group":"2"},"group_map2":{"role":"","group":"3"},"group_map3":{"role":"x","group":"0"}}');
        self::assertSame([['admin', 6], ['member', 2]], GroupMapper::rules($stored));
        self::assertSame([['admin', 6]], GroupMapper::rules('[{"role":"admin","group":6}]'));
        self::assertSame([], GroupMapper::rules(null));
    }

    public function testResolveGivesEveryMatchingGroupOrTheDefault(): void
    {
        $rules = [['admin', 6], ['editor', 4], ['admin', 4], ['member', 2]];
        self::assertSame([6, 4], GroupMapper::resolve($rules, ['admin'], 2));
        self::assertSame([6, 4, 2], GroupMapper::resolve($rules, ['member', 'admin'], 9));
        self::assertSame([9], GroupMapper::resolve($rules, ['guest'], 9));
        self::assertSame([9], GroupMapper::resolve([], ['admin'], 9));
    }

    public function testSyncManagesOnlyTheMappedGroups(): void
    {
        $rules = [['admin', 6], ['member', 2]];
        // The user lost "admin": group 6 goes, the unmapped group 10 stays, member's group 2 comes.
        self::assertSame([10, 2], GroupMapper::sync($rules, [6, 10], ['member'], 2));
        // No role matches and nothing else: the default group.
        self::assertSame([2], GroupMapper::sync($rules, [6], ['guest'], 2));
        self::assertSame([10], GroupMapper::sync($rules, [10, 6], [], 2));
        self::assertSame([6, 2], GroupMapper::sync($rules, ['6', '2'], ['admin', 'member'], 2));
    }
}
