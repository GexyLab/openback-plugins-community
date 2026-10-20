<?php

declare(strict_types=1);

namespace OpenBack\AppAuth\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use OpenBack\AppAuth\AppAuthException;
use OpenBack\AppAuth\Http\CurlTransport;
use OpenBack\AppAuth\Http\HttpResponse;
use OpenBack\AppAuth\Http\Psr18Transport;
use OpenBack\AppAuth\Http\Transport;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class TransportTest extends TestCase
{
    public function testPsr18TransportSendsTheRequest(): void
    {
        $client = new class implements ClientInterface {
            public ?RequestInterface $request = null;
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->request = $request;
                return new Response(201, ['Content-Type' => 'application/json', 'X-Multi' => ['a', 'b']], '{"ok":true}');
            }
        };
        $factory = new Psr17Factory();
        $transport = Transport::fromOptions(['httpClient' => $client, 'requestFactory' => $factory]);
        self::assertInstanceOf(Psr18Transport::class, $transport);
        $response = $transport->send('post', 'https://example.com/x', ['X-Client-Id' => 'uapp_1'], '{"a":1}');
        self::assertSame('POST', $client->request->getMethod());
        self::assertSame('uapp_1', $client->request->getHeaderLine('X-Client-Id'));
        self::assertSame('{"a":1}', (string) $client->request->getBody());
        self::assertSame(201, $response->status);
        self::assertSame(['ok' => true], $response->json());
        self::assertSame('a, b', $response->header('x-multi'));
    }

    public function testDefaultIsCurl(): void
    {
        if (!function_exists('curl_init')) {
            self::markTestSkipped('ext-curl not installed');
        }
        self::assertInstanceOf(CurlTransport::class, Transport::fromOptions([]));
    }

    public function testCurlNetworkErrorIsAnAppAuthException(): void
    {
        if (!function_exists('curl_init')) {
            self::markTestSkipped('ext-curl not installed');
        }
        try {
            (new CurlTransport(2, 2))->send('GET', 'http://127.0.0.1:9/nothing-listens-here');
            self::fail('no error');
        } catch (AppAuthException $e) {
            self::assertSame(0, $e->status);
            self::assertSame('network_error', $e->errorCode);
        }
    }

    public function testCurlRefusesOtherSchemes(): void
    {
        if (!function_exists('curl_init')) {
            self::markTestSkipped('ext-curl not installed');
        }
        $this->expectException(AppAuthException::class);
        (new CurlTransport())->send('GET', 'file:///etc/passwd');
    }

    public function testHttpResponseJson(): void
    {
        self::assertNull((new HttpResponse(200, [], 'not json'))->json());
        self::assertNull((new HttpResponse(204))->json());
        self::assertSame([1, 2], (new HttpResponse(200, [], '[1,2]'))->json());
    }
}
