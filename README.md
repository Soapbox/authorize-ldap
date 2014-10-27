# Authorize-LDAP
[Authorize](http://github.com/soapbox/authorize-ldap) strategy for LDAP authentication.

## Getting Started
- Install [Authorize](http://github.com/soapbox/authorize) into your application
to use this Strategy.

## Installation
Add the following to your `composer.json`
```
"require": {
	...
	"soapbox/authorize-ldap": "1.*",
	...
}
```

### app/config/app.php
Add the following to your `app.php`, note this will be removed in future
versions since it couples us with Laravel, and it isn't required for the library
to function
```
'providers' => array(
	...
	"SoapBox\AuthorizeLdap\AuthorizeLdapServiceProvider",
	...
)
```

## Usage

### Login (Regular)
```php

use SoapBox\Authroize\Authenticator;
use SoapBox\Authorize\Exceptions\InvalidStrategyException;
...
$settings = [
	'connection' => [
		'url' => 'ldap://192.168.50.4',
		'port' => '3890'
	],
	'application' => [
		'username' => 'cn=admin,dc=puppetlabs,dc=test',
		'password' => 'test'
	]
];

//If you already have an accessToken from a previous authentication attempt

$strategy = new Authenticator('ldap', $settings);

$parameters = [
	'username' => 'provided_by_user',
	'password' => 'provided_by_user',
	'search' => [
		'query' => '(uid={username})' // Note username will be replaced with the above username
		'base' => 'dc=puppetlabs,dc=test'
	],
	'parameters_map' => [
		'id' => 'dn',
		'display_name' => 'cn',
		'email' => 'mail',
		'username' => 'mail',
		'firstname' => 'cn',
		'lastname' => 'sn',
		'customParam' => 'extractmeeeee'
	]
];

$user = $strategy->authenticate($parameters);
```

### Login (NTML)

Note if you plan to use NTML to authenticate you should retrieve the username from:

```php
$ntlm = explode('\\', $_SERVER['REMOTE_USER']);
$username = $ntml[1];
```

Additionally there's a tutorial for configuring your server at http://carpepm.net/sharepoint-sso-ntlm-from-apache-ubuntu/

```php

use SoapBox\Authroize\Authenticator;
use SoapBox\Authorize\Exceptions\InvalidStrategyException;
...
$settings = [
	'connection' => [
		'url' => 'ldap://192.168.50.4',
		'port' => '3890'
	],
	'application' => [
		'username' => 'cn=admin,dc=puppetlabs,dc=test',
		'ntml' => true
	]
];

//If you already have an accessToken from a previous authentication attempt

$strategy = new Authenticator('ldap', $settings);

$parameters = [
	'username' => 'provided_by_user',
	'ntml' => true,
	'search' => [
		'query' => '(uid={username})' // Note username will be replaced with the above username
		'base' => 'dc=puppetlabs,dc=test'
	],
	'parameters_map' => [
		'id' => 'dn',
		'display_name' => 'cn',
		'email' => 'mail',
		'username' => 'mail',
		'firstname' => 'cn',
		'lastname' => 'sn',
		'customParam' => 'extractmeeeee'
	]
];

$user = $strategy->authenticate($parameters);
```
