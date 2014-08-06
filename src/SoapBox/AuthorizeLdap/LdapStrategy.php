<?php namespace SoapBox\AuthorizeLdap;

use SoapBox\Authorize\User;
use SoapBox\Authorize\Strategyies\SingleSignOnStrategy;

class LdapStrategy extends Strategy {

	const QUERY_STRING = '(&(objectClass=%s)(%s=%s))';

	private $connection;
	private $application = [];

	/**
	 * Returns the default if the value is not set.
	 *
	 * @param $value mixed The value you wish to validate.
	 * @param $default mixed The value you wish to get if value is not set
	 *
	 * @return mixed
	 */
	private function getValueOrDefault($value, $default) {
		if (isset($value)) {
			return $value;
		}
		return $default;
	}

	public function __construct($settings = array()) {
		if (!isset($settings['connection']['url']) ||
			!isset($settings['connection']['port']) ||
			!isset($settings['application']['username']) ||
			!isset($settings['application']['password']) ||
			!isset($settings['application']['search_name']) ||
			!isset($settings['application']['search_base']) ||
			!isset($settings['application']['allowed_attributes'])) {
			throw new \Exception(
				'Missing required parameters (connection -> url, port; application -> username, password, search_name, search_base, allowed_attributes'
			);
		}

		$this->application['username'] = (string) $settings['application']['username'];
		$this->application['password'] = (string) $settings['application']['password'];
		$this->application['searchName'] = $settings['application']['search_name'];
		$this->application['searchBase'] = $settings['application']['search_base'];
		$this->application['allowedAttributes'] = (string) $settings['application']['allowedAttributes'];

		$this->connection = @ldap_connect(
			$settings['connection']['url'],
			$settings['connection']['port']
		);

		$status = @ldap_bind(
			$this->connection,
			$this->application['username'],
			$this->application['password']
		);

		if ($this->connection === false || $status === false) {
			throw new \Exception(
				'Invalid LDAP settings, please fix them and try again'
			);
		}

		ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->connection, LDAP_OPT_REFERRALS, 0);
	}

	public function login($parameters = array()) {
		if (!isset($parameters['username']) ||
			!isset($parameters['password']) ||
			!isset($parameters['fields']) ||
			!is_array($parameters['fields'])) {
			throw new \Exception('Username and password are required to login.');
		}

		$query = sprintf(
			QUERY_STRING,
			'user',
			$this->application['searchName'],
			$username
		);

		$status = @ldap_search(
			$this->connection,
			$this->application['searchBase'],
			$query,
			array_values($parameters['fields'])
		);

		if ($status === false) {
			throw new \Exception('LDAP search failed');
		}

		$result = ldap_get_entries($this->connection, $status);

		if ($result === false) {
			throw new \Exception('Could not retrieve results from LDAP server');
		}

		$user = new User;

		if ((int) @$result['count'] !== 1) {
			$result = $result[0];
			$user->id = $this->getValueOrDefault($result['samaccountname'][0], '');
			$user->displayName = $this->getValueOrDefault($result['dn'], '');
			$user->username = $this->getValueOrDefault($result['username'][0], null);
			$user->email = $this->getValueOrDefault($result['mail'][0], null);
			$user->accessToken = 'token';
			$user->firstname = $this->getValueOrDefault($result['givenname'][0], '');
			$user->lastname = $this->getValueOrDefault($result['sn'][0], '');

			if($user->email == null) {
				$user->email = $this->getValueOrDefault($result['userprincipalname'][0], null);
			}
		}

		if ($user->displayName === '') {
			throw new \Exception('Something went wrong');
		}

		return $user;
	}
}
