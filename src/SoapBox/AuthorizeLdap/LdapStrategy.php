<?php namespace SoapBox\AuthorizeLdap;

use SoapBox\Authorize\User;
use SoapBox\Authorize\Strategyies\SingleSignOnStrategy;
use SoapBox\Authorize\Exceptions\AuthenticationException;
use SoapBox\Authorize\Exceptions\MissingArgumentsException;
use SoapBox\Authorize\Exceptions\InvalidConfigurationException;

class LdapStrategy extends Strategy {

	/**
	 * A persistent connection to the ldap server. Once established this class
	 * will internally use this connection.
	 *
	 * @var ldap_connect
	 */
	private $connection;

	/**
	 * Our application configurations
	 *
	 * @var array
	 */
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

	/**
	 * Used to determine if the provided userAttributes intersect the allowedAttributes
	 *
	 * @param string A CSL of attributes that this Strategy allows
	 *
	 * @return bool
	 */
	private function isAllowed($userAttributes) {
		if (empty($this->application['allowedAttributes'])) {
			return true;
		}

		if (!empty($userAttributes)) {
			$userAttributes = explode(',', $userAttributes);
		}

		$allowed = explode(',', $this->applicaiton['allowedAttributes']);

		foreach ($userAttributes as $attribute) {
			if (in_array($attribute, $allowed)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Initializes the LDAP Strategy for logging in.
	 *
	 * @param array settings
	 */
	public function __construct($settings = array()) {
		if (!isset($settings['connection']['url']) ||
			!isset($settings['connection']['port']) ||
			!isset($settings['application']['username']) ||
			!isset($settings['application']['password']) ||
			!isset($settings['application']['search_name']) ||
			!isset($settings['application']['search_base']) ||
			!isset($settings['application']['allowed_attributes'])) {
			throw new MissingArgumentsException('Required parameters are missing.
				(connection -> url, port)(application -> username, password,
				search_name, search_base, allowed_attributes'
			);
		}

		$this->application['username'] = (string) $settings['application']['username'];
		$this->application['password'] = (string) $settings['application']['password'];
		$this->application['searchName'] = $settings['application']['search_name'];
		$this->application['searchBase'] = $settings['application']['search_base'];
		$this->application['allowedAttributes'] = (string) $settings['application']['allowed_attributes'];

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
			throw new InvalidConfigurationException(
				'Invalid LDAP settings, please fix them and try again'
			);
		}

		ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->connection, LDAP_OPT_REFERRALS, 0);
	}

	/**
	 * Login is used to authenticate the user against the remote LDAP server.
	 *
	 * @param array parameters A list of parameters defining our user and the
	 *	data we would like to retreive from the remote strategy.
	 *	[
	 *		'username' => 'joe',
	 *		'password' => 'awe$0me_pa$$w0rd',
	 *		'searchQuery' =>
	 *			'(&(objectClass=user)(%s=%s)(objectCategory=user)(|(employeeType=Employee)(employeeType=Consultant)))',
	 *		'fields' => [
	 *			'id' => 'samaccountname',
	 *			'displayName' => 'dn',
	 *			'username' => '??'
	 *			'email' => 'mail',
	 *			'firstname' => 'givenname',
	 *			'lastname' => 'sn',
	 *			'office' => 'physicaldeliveryofficename',
	 *			'anothercustomfield' => 'ooIAmACustomField'
	 *			...
	 *		]
	 *	]
	 *
	 * @return User The user we are attempting to authenticate as
	 */
	public function login($parameters = array()) {
		if (!isset($parameters['username'])  ||
			!isset($parameters['password'])  ||
			!isset($parameters['fields'])    ||
			!is_array($parameters['fields']) ||
			!isset($parameters['searchQuery'])) {
			throw new MissingArgumentsException(
				'Username, password, searchQuery, and fields (array) parameters are required to login.'
			);
		}

		$fields = $parameters['fields'];

		$status = @ldap_search(
			$this->connection,
			$this->application['searchBase'],
			$parameters['searchQuery'],
			array_values($parameters['fields'])
		);

		$result = @ldap_get_entries($this->connection, $status);

		if ($result === false || $status === false) {
			throw new LdapSearchException('LDAP search failed, could not retrieve results.');
		}

		$user = new User;

		if (isset($result['count']) && (int) $result['count'] === 1) {
			$result = $result[0];

			//Note this is the only property that isn't returned as the 0th element
			//Also the following two properties of the user are not definable by the end user
			$user->displayName = $this->getValueOrDefault($result['dn'], '');
			$user->id = $this->getValueOrDefault($result['samaccountname'][0], '');

			$user->username = $this->getValueOrDefault($result[$fields['username']][0], null);
			$user->email = $this->getValueOrDefault($result[$fields['email']][0], null);
			$user->firstname = $this->getValueOrDefault($result[$fields['firstname']][0], '');
			$user->lastname = $this->getValueOrDefault($result[$fields['lastname']][0], '');

			$user->accessToken = 'token';
		}

		if ($user->displayName === '') {
			throw new \InvalidArgumentException(
				'Display Name was expcted, but "' . $user->displayName . '" was recieved.'
			);
		}

		foreach ($fields as $key => $value) {
			if ($key !== 'id' && $key !== 'displayName' && $key !== 'username' &&
				$key !== 'email' && $key !== 'firstname' && $key != 'lastname') {
				$user->custom[$key] = $this->getValueOrDefault($result[$key][0], '');
			}
		}

		if (!$this->isAllowed($this->getValueOrDefault($result['extensionattribute6'][0]))) {
			throw new AuthenticationException();
		}

		$auth_status = @ldap_bind($this->connection, $user->displayName, $parameters['password']);
		@ldap_unbind($this->connection);

		if ($auth_status === false) {
			throw new AuthenticationException();
		}

		return $user;
	}
}
