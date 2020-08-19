<?php

namespace Benjaminhu\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class QuickBooksOnline extends AbstractProvider
{
	/**
	 * @var string Key used in a token response to identify the resource owner.
	 */
	const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'user_id';

	/**
	 * Base URL
	 *
	 * @var string
	 */
	public $baseUrl = 'https://appcenter.intuit.com/connect/oauth2';

	/**
	 * Get authorization url to begin OAuth flow
	 *
	 * @return string
	 */
	public function getBaseAuthorizationUrl()
	{
		return 'https://appcenter.intuit.com/connect/oauth2';
	}

	/**
	 * Get access token url to retrieve token
	 *
	 * @param  array $params
	 *
	 * @return string
	 */
	public function getBaseAccessTokenUrl(array $params)
	{
		return 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
	}


	/**
	 * Get provider url to fetch user details
	 *
	 * @param  AccessToken $token
	 *
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token)
	{
		return $this->getAuthenticatedUrlForEndpoint('/current_user', $token);
	}

	/**
	 * Returns a prepared request for requesting an access token.
	 *
	 * @param array $params Query string parameters
	 * @return RequestInterface
	 */
	protected function getAccessTokenRequest(array $params)
	{
		$token = null;
		// need getAuthorizationHeaders() to refresh token
		if (isset($params['access_token'])) {
			$token  = $params['access_token'];
		}
		$method  = $this->getAccessTokenMethod();
		$url     = $this->getAccessTokenUrl($params);
		$options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), $params);
		return $this->createRequest($method, $url, $token, $options);
	}

	/**
	 * Requests an access token using a specified grant and option set.
	 *
	 * @param  mixed $grant
	 * @param  array $options
	 * @throws IdentityProviderException
	 * @return AccessTokenInterface
	 */
	public function getAccessToken($grant, array $options = [])
	{
		$grant = $this->verifyGrant($grant);

		$params = [
			'redirect_uri'  => $this->redirectUri,
		];

		$params   = $grant->prepareRequestParameters($params, $options);
		$request  = $this->getAccessTokenRequest($params);
		$response = $this->getParsedResponse($request);
		if (false === is_array($response)) {
			throw new UnexpectedValueException(
				'Invalid response received from Authorization Server. Expected JSON.'
			);
		}
		$prepared = $this->prepareAccessTokenResponse($response);
		$token    = $this->createAccessToken($prepared, $grant);

		return $token;
	}

	/**
	 * Get the full uri with appended oauth_token query string
	 *
	 * @param string $endpoint | with leading slash
	 * @param AccessToken $token
	 * @return string
	 */
	public function getAuthenticatedUrlForEndpoint($endpoint, AccessToken $token)
	{
		return $this->baseUrl . $endpoint . '?oauth_token=' . $token->getToken();
	}

	/**
	 * @return array
	 */
	protected function getDefaultScopes()
	{
		return array('com.intuit.quickbooks.accounting');
	}

	protected function checkResponse(ResponseInterface $response, $data)
	{
		$statusCode = $response->getStatusCode();
		if ($statusCode >= 400) {
			throw new IdentityProviderException(
				isset($data[0]['message']) ? $data[0]['message'] : $response->getReasonPhrase(),
				$statusCode,
				$response
			);
		}
	}

	protected function createResourceOwner(array $response, AccessToken $token)
	{
		$owner_id = $token->getResourceOwnerId();
		if (isset($response['results']['users'][$owner_id])) {
			$response = $response['results']['users'][$owner_id];
		}
		return new QuickBooksOnlineResourceOwner($response);
	}

	/**
	 * Returns the default headers used by this provider.
	 *
	 * Typically this is used to set 'Accept' or 'Content-Type' headers.
	 *
	 * @return array
	 */
	protected function getDefaultHeaders()
	{
		$header = [
			'Authorization' => 'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)
		];
		return $header;
	}

	/**
	 * Adds token to headers
	 *
	 * @param AccessToken $token
	 * @return array
	 */
	protected function getAuthorizationHeaders($token = null) {
		$header = [];
		if (isset($token)) {
			$header['Authorization'] = 'Bearer ' . $token->getToken();
		}
		return $header;
	}
}
