<?php
/**
 * @author Noveen Sachdeva <noveen.sachdeva@research.iiit.ac.in>
 *
 * @copyright Copyright (c) 2017, ownCloud GmbH
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

namespace OCA\DAV\Connector\Sabre;

use Sabre\HTTP\ResponseInterface;
use Sabre\HTTP\RequestInterface;

/**
 * Class CorsPlugin is a plugin which adds CORS headers to the responses
 */
class CorsPlugin extends \Sabre\DAV\ServerPlugin {

	/**
	 * Reference to main server object
	 *
	 * @var \Sabre\DAV\Server
	 */
	private $server;

	/**
	 * This initializes the plugin.
	 *
	 * This function is called by \Sabre\DAV\Server, after
	 * addPlugin is called.
	 *
	 * This method should set up the required event subscriptions.
	 *
	 * @param \Sabre\DAV\Server $server
	 * @return void
	 */
	public function initialize(\Sabre\DAV\Server $server) {
		$this->server = $server;
		$this->server->on('beforeMethod', [$this, 'setCorsHeaders'], 100);
		$this->server->on('beforeMethod:OPTIONS', [$this, 'setOptionsRequestHeaders'], 5);
	}

	/**
	 * This method sets the cors headers for all requests
	 *
	 * @return void
	 */
	public function setCorsHeaders() {
		if (isset(\OC::$server->getRequest()->server['HTTP_ORIGIN']) &&
			\OC::$server->getUserSession()) {
			$requesterDomain = \OC::$server->getRequest()->server['HTTP_ORIGIN'];
			$userId = \OC::$server->getUserSession()->getUser()->getUID();
			\OC_Response::setCorsHeaders($userId, $requesterDomain);
		}
	}

	/**
	 * Handles the OPTIONS request
	 *
	 * @param RequestInterface $request
	 * @param ResponseInterface $response
	 *
	 * @return false
	 */
	public function setOptionsRequestHeaders(RequestInterface $request, ResponseInterface $response) {
		\OC_Response::setOptionsRequestHeaders();

		$response->setStatus(200);

		if (!isset(\OC::$server->getRequest()->server['PHP_AUTH_USER'])) {
			// Non-authenticated request
			return false;
		}
	}
}
