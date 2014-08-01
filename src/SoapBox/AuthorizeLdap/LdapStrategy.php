<?php namespace SoapBox\AuthorizeLdap;

use SoapBox\Authorize\Strategyies\SingleSignOnStrategy;

class LdapStrategy extends SingleSignOnStrategy {

	private $connection;
	private $application = [];

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

}
