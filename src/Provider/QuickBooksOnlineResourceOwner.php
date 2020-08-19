<?php

namespace Benjaminhu\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;

class QuickBooksOnlineResourceOwner implements ResourceOwnerInterface
{
	protected $response;

	public function __construct(array $response)
	{
		$this->response = $response;
	}

	/**
	 * Get resource owner id
	 *
	 * @return string|null
	 */
	public function getId()
	{
		return $this->response['id'] ?: null;
	}

	/**
	 * Get user username
	 *
	 * @return string|null
	 */
	public function getUsername()
	{
		return $this->response['username'] ?: null;
	}

	/**
	 * Return all of the owner details available as an array.
	 *
	 * @return array
	 */
	public function toArray()
	{
		return $this->response;
	}
}
