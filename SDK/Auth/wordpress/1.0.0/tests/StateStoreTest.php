<?php

declare(strict_types=1);

use OpenBackAppAuthWp\StateBackend;
use OpenBackAppAuthWp\StateStore;
use PHPUnit\Framework\TestCase;

final class StateStoreTest extends TestCase
{
	private ?string $cookie = null;
	private int $now = 1_800_000_000;
	private StateBackend $backend;

	protected function setUp(): void
	{
		$this->backend = new class implements StateBackend {
			public array $data = [];

			public function get(string $key): ?array
			{
				return $this->data[$key] ?? null;
			}

			public function set(string $key, array $value, int $ttl_seconds): void
			{
				$this->data[$key] = $value;
			}

			public function delete(string $key): void
			{
				unset($this->data[$key]);
			}
		};
	}

	private function store(): StateStore
	{
		return new StateStore(
			$this->backend,
			fn () => $this->cookie,
			function (string $value, int $ttl) {
				$this->cookie = $value;
			},
			fn () => $this->now
		);
	}

	public function testPutAndTakeOnce(): void
	{
		$store = $this->store();
		$store->put(['state' => 'abc', 'nonce' => 'n', 'redirect_to' => '/x']);
		self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', (string) $this->cookie);
		// Server-side only: the cookie holds a random id; the backend key is its hash, the data is not in the cookie.
		self::assertArrayHasKey(StateStore::key((string) $this->cookie), $this->backend->data);
		self::assertStringNotContainsString('abc', (string) $this->cookie);

		self::assertSame('/x', $store->take('abc')['redirect_to']);
		self::assertNull($store->take('abc'), 'one use');
		self::assertSame([], $this->backend->data, 'nothing left');
	}

	public function testSeveralTabsAndWrongState(): void
	{
		$store = $this->store();
		$store->put(['state' => 's1']);
		$store->put(['state' => 's2']);
		self::assertNull($store->take('s3'));
		self::assertNull($store->take(''));
		self::assertNull($store->take(null));
		self::assertSame('s2', $store->take('s2')['state']);
		self::assertSame('s1', $store->take('s1')['state']);
	}

	public function testAtMostFivePerBrowser(): void
	{
		$store = $this->store();
		for ($i = 1; $i <= 7; $i++) {
			$store->put(['state' => "s$i"]);
		}
		self::assertNull($store->take('s1'));
		self::assertNull($store->take('s2'));
		self::assertNotNull($store->take('s3'));
		self::assertNotNull($store->take('s7'));
	}

	public function testExpiry(): void
	{
		$store = $this->store();
		$store->put(['state' => 'old']);
		$this->now += StateStore::TTL + 1;
		self::assertNull($store->take('old'));
	}

	public function testAnotherBrowserCannotTakeIt(): void
	{
		$store = $this->store();
		$store->put(['state' => 'mine']);
		$this->cookie = str_repeat('A', 43);           // another browser's id
		self::assertNull($store->take('mine'));
		$this->cookie = 'not valid!';
		self::assertNull($store->take('mine'));
		$this->cookie = null;
		self::assertNull($store->take('mine'));
	}

	public function testStateIsRequired(): void
	{
		$this->expectException(InvalidArgumentException::class);
		$this->store()->put(['nonce' => 'n']);
	}
}
