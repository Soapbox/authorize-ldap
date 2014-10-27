<?php namespace SoapBox\AuthorizeLdap;

use Illuminate\Support\ServiceProvider;
use SoapBox\Authorize\StrategyFactory;

class AuthorizeLdapServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = true;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot()
	{
		$this->package('soapbox/authorize-ldap');
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register() {
		$this->app->bind(
			'soapbox.authorize.ldap',
			'SoapBox\AuthorizeLdap\LdapStrategy'
		);
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides() {
		return ['soapbox.authorize.ldap'];
	}

}
