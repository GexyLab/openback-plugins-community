<?php

declare(strict_types=1);

use OpenBackAppAuthWp\RoleMapper;
use PHPUnit\Framework\TestCase;

final class RoleMapperTest extends TestCase
{
	public function testParse(): void
	{
		$rules = RoleMapper::parse("# comment\n admin = Editor \n\nmember:subscriber\nbroken line\n= author\nx = bad role!\r\nowner=administrator");
		self::assertSame([['admin', 'editor'], ['member', 'subscriber'], ['owner', 'administrator']], $rules);
	}

	public function testFirstMatchingRuleWins(): void
	{
		$rules = RoleMapper::parse("owner = administrator\nadmin = editor\nmember = subscriber");
		self::assertSame('editor', RoleMapper::resolve($rules, ['member', 'admin'], 'subscriber'));
		self::assertSame('administrator', RoleMapper::resolve($rules, ['admin', 'owner'], 'subscriber'));
		self::assertSame('contributor', RoleMapper::resolve($rules, ['guest'], 'contributor'));
		self::assertSame('contributor', RoleMapper::resolve($rules, [], 'contributor'));
	}

	public function testRolesAreCaseSensitiveOnTheOpenBackSide(): void
	{
		self::assertSame('subscriber', RoleMapper::resolve(RoleMapper::parse('Admin = editor'), ['admin'], 'subscriber'));
	}

	public function testMissingWordPressRolesAreSkipped(): void
	{
		$rules = RoleMapper::parse("admin = shop_manager\nadmin = editor");
		self::assertSame('editor', RoleMapper::resolve($rules, ['admin'], 'subscriber', ['editor', 'subscriber']));
	}

	public function testNormalize(): void
	{
		[$text, $refused] = RoleMapper::normalize("admin=editor\nmember = ghost\n# x", ['editor', 'subscriber']);
		self::assertSame('admin = editor', $text);
		self::assertSame(['member = ghost'], $refused);
	}
}
