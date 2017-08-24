<?php
/**
 * @author Noveen Sachdeva <noveen.sachdeva@research.iiit.ac.in>
 *
 * @copyright Copyright (c) 2015, ownCloud, Inc.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace Tests\Settings\Controller;

use OC\Settings\Controller\CorsController;
use OCP\AppFramework\Http\JSONResponse;
use Test\TestCase;
use OCP\IRequest;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IURLGenerator;
use OCP\AppFramework\Http\RedirectResponse;

/**
 * Class CorsControllerTest
 *
 * @package Tests\Settings\Controller
 */
class CorsControllerTest extends TestCase {
	/** @var CorsController */
	private $corsController;

	/** @var IRequest */
	private $request;

	/** @var ILogger */
	private $logger;

	/** @var IURLGenerator */
	private $urlGenerator;

	/** @var IConfig */
	private $config;

	public function setUp() {
		parent::setUp();

		$this->request = $this->createMock(IRequest::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->urlGenerator = $this->createMock(IURLGenerator::class);
		$this->config = $this->createMock(IConfig::class);

		$this->corsController = new CorsController(
			'core',
			$this->request,
			'user',
			$this->logger,
			$this->urlGenerator,
			$this->config
		);
	}

	public function testAddInvalidDomain() {
		// Since this domain is invalid,
		// the success message that the domain is white-listed, wouldn't be triggered
		$this->logger
			->expects($this->never())
			->method('debug');

		$this->config
			->expects($this->never())
			->method("setUserValue");

		$response = $this->corsController->addDomain("non-valid domain");

		$expectedResponse = new RedirectResponse(
			$this->urlGenerator->linkToRouteAbsolute(
				'settings.SettingsPage.getPersonal',
				['sectionid' => 'security']
			) . '#cors'
		);

		$this->assertEquals($response, $expectedResponse);
	}

	public function testAddValidDomain() {
		// Since this domain is valid,
		// the success message that the domain is white-listed, would be triggered exactly once
		$this->logger
			->expects($this->once())
			->method('debug');

		$this->config
			->expects($this->once())
			->method("setUserValue");

		$response = $this->corsController->addDomain("http://www.testDomain.com");

		$expectedResponse = new RedirectResponse(
			$this->urlGenerator->linkToRouteAbsolute(
				'settings.SettingsPage.getPersonal',
				['sectionid' => 'security']
			) . '#cors'
		);

		$this->assertEquals($response, $expectedResponse);
	}

	public function testRemoveInvalidDomain() {
		// Since this domain id passed is invalid,
		// the error message that invalid domain ID passed, would be triggered
		$this->logger
			->expects($this->once())
			->method('error');

		$this->config
			->expects($this->never())
			->method("setUserValue");

		// The argument for removing domain is the ID of the white-listed domain
		// and not the domain itself
		$response = $this->corsController->removeDomain(100);

		$expectedResponse = new RedirectResponse(
			$this->urlGenerator->linkToRouteAbsolute(
				'settings.SettingsPage.getPersonal',
				['sectionid' => 'security']
			) . '#cors'
		);

		$this->assertEquals($response, $expectedResponse);
	}

	public function testRemoveValidDomain() {
		// Since this domain-ID is valid,
		// the error message that invalid domain ID passed, would never be triggered
		$this->logger
			->expects($this->never())
			->method('error');

		$this->config
			->expects($this->once())
			->method("setUserValue");

		// The argument for removing domain is the ID of the white-listed domain
		// and not the domain itself
		$response = $this->corsController->removeDomain(0);

		$expectedResponse = new RedirectResponse(
			$this->urlGenerator->linkToRouteAbsolute(
				'settings.SettingsPage.getPersonal',
				['sectionid' => 'security']
			) . '#cors'
		);

		$this->assertEquals($response, $expectedResponse);
	}

	public function testGetDomains() {
		// since their are no domains, empty JSON response will be sent back
		$expected = new JSONResponse([]);
		$this->assertEquals($expected, $this->corsController->getDomains());
	}
}
