<?php namespace SoapBox\AuthorizeLdap;

class Helpers {

	private static function escapeString($string = '') {
		$meta_chars = array ('\\00', '\\', '(', ')', '*');
		$quoted_meta_chars = array ();

		foreach ($meta_chars as $key => $value) {
			$quoted_meta_chars[$key] = '\\'. dechex(ord($value));
		}

		$result = str_replace ( $meta_chars, $quoted_meta_chars, $string ); //replace them

		return ($result);
	}

	public static function sanitize($string = '') {
		return Helpers::escapeString($string);
	}

}
