<?php

declare(strict_types=1);

use OpenBackAppAuthJoomla\Integration\PendingSignIns;
use OpenBackAppAuthJoomla\Integration\VerifiedLogin;
use PHPUnit\Framework\TestCase;

final class PendingSignInsTest extends TestCase
{
    private const NOW = 1_800_000_000;

    public function testAddAndTakeOnce(): void
    {
        $list = PendingSignIns::add([], ['state' => 's1', 'return' => '/a'], self::NOW);
        $list = PendingSignIns::add($list, ['state' => 's2', 'return' => '/b'], self::NOW);
        [$tx, $list] = PendingSignIns::take($list, 's1', self::NOW + 10);
        self::assertSame('/a', $tx['return']);
        [$tx, $list] = PendingSignIns::take($list, 's1', self::NOW + 10);
        self::assertNull($tx, 'one use');
        [$tx, $list] = PendingSignIns::take($list, 's2', self::NOW + 10);
        self::assertSame('/b', $tx['return']);
        self::assertSame([], $list);
    }

    public function testWrongStateExpiryAndLimit(): void
    {
        $list = [];
        for ($i = 1; $i <= 7; $i++) {
            $list = PendingSignIns::add($list, ['state' => "s$i"], self::NOW);
        }
        self::assertCount(PendingSignIns::MAX, $list);
        self::assertNull(PendingSignIns::take($list, 's1', self::NOW)[0]);
        self::assertNull(PendingSignIns::take($list, null, self::NOW)[0]);
        self::assertNull(PendingSignIns::take($list, '', self::NOW)[0]);
        self::assertNull(PendingSignIns::take($list, 'nope', self::NOW)[0]);
        self::assertNotNull(PendingSignIns::take($list, 's7', self::NOW)[0]);
        [$tx, $left] = PendingSignIns::take($list, 's7', self::NOW + PendingSignIns::TTL + 1);
        self::assertNull($tx);
        self::assertSame([], $left, 'expired entries are dropped');
        self::assertNull(PendingSignIns::take([['garbage'], 'x', null], 's1', self::NOW)[0]);
    }

    public function testStateIsRequired(): void
    {
        $this->expectException(InvalidArgumentException::class);
        PendingSignIns::add([], ['nonce' => 'n'], self::NOW);
    }

    public function testVerifiedLoginIsUsableOnce(): void
    {
        $login = new VerifiedLogin(42, 'ada');
        self::assertTrue($login->consume());
        self::assertFalse($login->consume());
    }
}
