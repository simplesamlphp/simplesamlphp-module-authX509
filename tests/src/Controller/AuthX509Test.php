<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\authX509\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Module\authX509\Controller;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "authX509" module.
 *
 * @package SimpleSAML\Test
 */
final class AuthX509Test extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => ['authx509' => true],
            ],
            '[ARRAY]',
            'simplesaml',
        );

        $this->session = Session::getSessionFromRequest();
    }


    /**
     * Test that request without StateId results in a BadRequest-error
     */
    public function testNoStateId(): void
    {
        $request = Request::create(
            '/expiryWarning',
            'GET',
        );

        $c = new Controller\ExpiryWarning($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing required StateId query parameter.');

        $c->main($request);
    }


    /**
     * Test that request without State results in a NOSTATE-error
     */
    public function testNoState(): void
    {
        $request = Request::create(
            '/expiryWarning',
            'GET',
            ['StateId' => 'SomeStateId'],
        );

        $c = new Controller\ExpiryWarning($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return null;
            }
        });

        $this->expectException(Error\NoState::class);
        $this->expectExceptionMessage('NOSTATE');

        $c->main($request);
    }


    /**
     * Test that request with 'proceed' param results in a RunnableResponse
     */
    public function testProceed(): void
    {
        $request = Request::create(
            '/expiryWarning',
            'GET',
            ['StateId' => 'SomeStateId', 'proceed' => 'pleaseProceed'],
        );

        $c = new Controller\ExpiryWarning($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [];
            }
        });

        $response = $c->main($request);

        // Validate response
        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     * Test that request without 'proceed' param results in a Template
     */
    public function testNotProceed(): void
    {
        $request = Request::create(
            '/expiryWarning',
            'GET',
            ['StateId' => 'SomeStateId', 'proceed'],
        );

        $c = new Controller\ExpiryWarning($this->config, $this->session);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return ['daysleft' => 10, 'renewurl' => 'https://example.org/renew'];
            }
        });

        $response = $c->main($request);

        // Validate response
        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());
    }
}
