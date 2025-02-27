<?php namespace SoapBox\AuthorizeLdap;

use StringTemplate\Engine;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Helpers;
use SoapBox\Authorize\Strategy;
use SoapBox\AuthorizeLdap\Helpers as LdapHelpers;
use SoapBox\Authorize\Exceptions\AuthenticationException;
use SoapBox\Authorize\Exceptions\MissingArgumentsException;
use SoapBox\Authorize\Exceptions\InvalidConfigurationException;
use SoapBox\AuthorizeLdap\Exceptions\UserNotFoundException;

class LdapStrategy implements Strategy {

	private $defaultFields = ['sAMAccountName'];

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
	 * Search result
	 *
	 * @var array
	 */
	private $result = [];

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

		$allowed = explode(',', $this->application['allowedAttributes']);

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
	 * @param callable $store A callback that will store a KVP (Key Value Pair).
	 * @param callable $load A callback that will return a value stored with the
	 *	provided key.
	 */
	public function __construct($settings = array(), $store = null, $load = null) {
		if (!isset($settings['connection']['url']) ||
			!isset($settings['connection']['port']) ||
			!isset($settings['application']['username']) ||
			!isset($settings['application']['password'])) {
			throw new MissingArgumentsException('Required parameters are missing.
				(connection -> url, port)(application -> username, password,
				search_name, search_base, allowed_attributes'
			);
		}

		$this->application['username'] = (string) $settings['application']['username'];
		$this->application['password'] = (string) $settings['application']['password'];

		if (isset($settings['application']['ntml'])) {
			$this->application['ntml'] = (bool) $settings['application']['ntml'];
		} else {
			$this->application['ntml'] = (bool) false;
		}

		$this->application['allowedAttributes'] =
			isset($settings['application']['allowed_attributes']) ?
				$settings['application']['allowed_attributes'] :
				'';

		if (empty($settings['connection']['port'])) {
			$this->connection = @ldap_connect($settings['connection']['url']);
		} else {
			$this->connection = @ldap_connect(
				$settings['connection']['url'],
				$settings['connection']['port']
			);
		}

		ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->connection, LDAP_OPT_REFERRALS, 0);

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
	}

	private function validateInput($parameters, $requiresPassword = false) {
		if (!isset($parameters['username'])        ||
			!isset($parameters['parameters_map'])    ||
			!is_array($parameters['parameters_map']) ||
			!isset($parameters['parameters_map']['id'])  ||
			!isset($parameters['parameters_map']['display_name'])  ||
			!isset($parameters['parameters_map']['username'])  ||
			!isset($parameters['parameters_map']['email'])     ||
			!isset($parameters['parameters_map']['firstname']) ||
			!isset($parameters['parameters_map']['lastname'])  ||
			!isset($parameters['search'])          ||
			!is_array($parameters['search'])       ||
			!isset($parameters['search']['query']) ||
			!isset($parameters['search']['base'])) {
			throw new MissingArgumentsException(
				'Required arguments are missing. Please ensure you have: username, parameters_map -> (id, display_name, username, email, firstname, lastname), search -> (query, base)'
			);
		}

		if ($requiresPassword) {
			if ( !(!$this->application['ntml'] && isset($parameters['password'])) ) {
				throw new MissingArgumentsException(
					'Required arguments are missing. Please ensure you have: (password || ntml)'
				);
			}
		}
	}

	/**
	 * Get the user from the remote LDAP server.
	 *
	 * @param array parameters A list of parameters defining our user and the
	 *	data we would like to retreive from the remote strategy.
	 *	[
	 *		'username' => 'joe',
	 *		'password' => 'awe$0me_pa$$w0rd',
	 *		'search' => [
	 *			'query' => '(uid={username})',
	 *			'base' => 'dc=puppetlabs,dc=test'
	 *		]
	 *		'parameters_map' => [
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
	 * @return User The user we are requesting
	 */
	public function getUser($parameters = array()) {
		$this->validateInput($parameters);

		$username = LdapHelpers::sanitize($parameters['username']);
		$engine = new Engine();

		$fields = $parameters['parameters_map'];
		$search = $parameters['search'];
		$query = $engine->render($search['query'], array('username' => $username));

		$status = @ldap_search(
			$this->connection,
			$search['base'],
			$query,
			array_values(array_merge($this->defaultFields, $fields))
		);

		$result = @ldap_get_entries($this->connection, $status);

		if ($result === false || $status === false) {
			throw new LdapSearchException('LDAP search failed, could not retrieve results.');
		}

		$user = new User;
		$dn = '';

		if (isset($result['count']) && (int) $result['count'] === 1) {
			$this->result = $result[0];

			//Note this is the only property that isn't returned as the 0th element
			//Also the following two properties of the user are not definable by the end user
			$dn = Helpers::getValueOrDefault($this->result['dn'], '', null);

			if ($fields['id'] == 'dn') {
				$user->id = $dn;
			} else {
				$user->id = Helpers::getValueOrDefault($this->result[$fields['id']], '', 0);
			}

			if ($fields['display_name'] == 'dn') {
				$user->displayName = $dn;
			} else {
				$user->displayName = Helpers::getValueOrDefault($this->result[$fields['display_name']], '', 0);
			}

			if ($fields['username'] == 'dn') {
				$user->username = $dn;
			} else {
				$user->username = Helpers::getValueOrDefault($this->result[$fields['username']], null, 0);
			}

			$user->email = Helpers::getValueOrDefault($this->result[$fields['email']], null, 0);
			$user->firstname = Helpers::getValueOrDefault($this->result[$fields['firstname']], '', 0);
			$user->lastname = Helpers::getValueOrDefault($this->result[$fields['lastname']], '', 0);

			$user->accessToken = 'token';

			$keys = ['id', 'display_name', 'username', 'email', 'firstname', 'lastname'];
			foreach ($keys as $key) {
				unset($fields[$key]);
			}
		}

		if ($dn === '') {
			throw new UserNotFoundException();
		}

		foreach ($fields as $key => $value) {
			if ($value != 'dn' && isset($this->result[$value])) {
				$user->custom[$key] = Helpers::getValueOrDefault($this->result[$value], '', 0);
			}
		}
		if (isset($this->result['extensionattribute6']) && !empty($this->result['extensionattribute6'])) {
			if (!$this->isAllowed(Helpers::getValueOrDefault($this->result['extensionattribute6'], '', 0))) {
				throw new AuthenticationException();
			}
		}

		return $user;
	}

	/**
	 * Login is used to authenticate the user against the remote LDAP server.
	 *
	 * @param array parameters A list of parameters defining our user and the
	 *	data we would like to retreive from the remote strategy.
	 *	[
	 *		'username' => 'joe',
	 *		'password' => 'awe$0me_pa$$w0rd',
	 *		'search' => [
	 *			'query' => '(uid={username})',
	 *			'base' => 'dc=puppetlabs,dc=test'
	 *		]
	 *		'parameters_map' => [
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

		$this->validateInput($parameters, true);
		$user = $this->getUser($parameters);
		$dn = Helpers::getValueOrDefault($this->result['dn'], '', null);

		if (isset($parameters['password'])) {
			$auth_status = @ldap_bind($this->connection, $dn, $parameters['password']);
		} else {
			$auth_status = (bool) $this->application['ntml'];
		}

		@ldap_unbind($this->connection);

		if ($auth_status === false) {
			throw new AuthenticationException();
		}

		return $user;
	}

	public static function validateSettings($settings = array()) {
		$errors = [];
		$actions = [
			'connected' => false,
			'authenticated' => false
		];

		$connection = false;

		if( !function_exists('ldap_connect') ) {
			$errors[] = "ldap_connect function does not exist";
		} else {
			try {
				$connection = ldap_connect(
					$settings['connection']['url'],
					$settings['connection']['port']
				);
				if ($connection != false) {
					$actions['connected'] = true;
				}
			} catch (\Exception $ex) {
				$errors[] = "Could not connect to URL / Port";
			}
		}

		if( !function_exists('ldap_bind') ) {
			$errors[] = "ldap_bind function does not exist";
		} else {
			if($connection != false) {
				try {
					ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
					ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);

					$bind = ldap_bind(
						$connection,
						$settings['application']['username'],
						$settings['application']['password']
					);

					if ($bind != false) {
						$actions['authenticated'] = true;
					}
				} catch (\Exception $ex) {
					$errors[] = "Could not connect to authenticate the application user / password. Check server url, port, username, and password.";
				}
			}
		}

		return [
			'actions' => $actions,
			'errors' => $errors
		];
	}
}
