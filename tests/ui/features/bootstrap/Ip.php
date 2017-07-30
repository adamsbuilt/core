<?php
/**
 * ownCloud
 *
 * @author Phil Davis <info@jankaritech.com>
 * @copyright 2017 Artur Neumann info@jankaritech.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
use TestHelpers\IpHelper;

trait Ip
{
	/**
	 * The local source IP address from which to initiate API actions.
	 * Defaults to system-selected address matching IP address family and scope.
	 * 
	 * @var string
	 */
	private $sourceIpAddress = null;
		
	/**
	 * @When the client accesses the server from a :networkScope :ipAddressFamily address
	 * @param string $networkScope (loopback|routable)
	 * @param string $ipAddressFamily (ipv4|ipv6)
	 * @return void
	 */
	public function theClientAccessesTheServerFromAddress(
		$networkScope, $ipAddressFamily
	) {
		$this->sourceIpAddress
				= IpHelper::ipAddress($networkScope, $ipAddressFamily);
	}

	/**
	 * @When the client accesses the server from IP address :sourceIpAddress
	 * @param string $sourceIpAddress an IPv4 or IPv6 address
	 * @return void
	 */
	public function theClientAccessesTheServerFromIpAddress($sourceIpAddress) {
		$this->sourceIpAddress = $sourceIpAddress;
	}

}