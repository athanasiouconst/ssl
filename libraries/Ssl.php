<?php
/**
 * Orange Framework Extension
 *
 * This content is released under the MIT License (MIT)
 *
 * @package	CodeIgniter / Orange
 * @author	Don Myers
 * @license	http://opensource.org/licenses/MIT	MIT License
 * @link	https://github.com/dmyers2004
 */
class Ssl {
	public $storage;
	protected $public;
	protected $private;
	protected $base64 = true; /* make it a little more portable */

	public function __construct() {
		$this->storage = __DIR__.'/keys';
		$this->private = $this->storage.'/private-key.txt';
		$this->public  = $this->storage.'/public-key.txt';
		
		@mkdir($this->storage,0777,true);
		
		/* if the keys aren't found then create them */
		if (!file_exists($this->private)) {
			$this->create_keys();
		}
	}

	public function migration_down() {
		@unlink($this->private);
		@unlink($this->public);
		@rmdir($this->storage);
	}

	public function force_ssl() {	
		// get the CI instance to access the CI resources
		$CI = & get_instance();

		// Change the base_url to have https prefix
		$CI->config->config['base_url'] = str_replace('http://', 'https://', $CI->config->config['base_url']);

		if ($_SERVER['SERVER_PORT'] != 443) {
			// redirect CI to use https URI
			// so that ($CI->uri->uri_string() return
			// the current URI with https prefix
			redirect($CI->uri->uri_string());
		}
	}

	public function remove_ssl() {	
		$CI = & get_instance();
		// Change the base_url to have http prefix
		$CI->config->config['base_url'] = str_replace('https://', 'http://', $CI->config->config['base_url']);

		if ($_SERVER['SERVER_PORT'] != 80) {
			// redirect CI to use http URI
			// so that ($CI->uri->uri_string() return
			// the current URI with http prefix
			redirect($CI->uri->uri_string());
		}
	}

	public function is_https() {	
		return ((!empty($_SERVER['HTTPS']) and strtolower($_SERVER['HTTPS']) !== 'off'));
	}

	public function base64() {	
		$this->base64 = true;

		return $this;
	}

	public function raw() {	
		$this->base64 = false;

		return $this;
	}

	public function encrypt($cleartext) {	
		$crypttext = '';

		$success = openssl_public_encrypt($cleartext, $crypttext, file_get_contents($this->public));

		return ($success) ? $this->encode($crypttext) : null;
	}

	public function decrypt($crypttext) {	
		$decrypted = '';

		$success = openssl_private_decrypt($this->decode($crypttext), $decrypted, file_get_contents($this->private));

		return ($success) ? $decrypted : null;
	}

	protected function create_keys() {	
		/* create any folder(s) that are needed depending on where we are storing the keys */
		if (!file_exists($this->storage)) {
			if (!mkdir($this->storage, 0777, true)) {
				show_error('Could not create OpenSSL key storage folder');
			}
		}

		/* Create the keypair */
		$res = openssl_pkey_new();

		if ($res === FALSE) {
			show_error('OpenSSL resource could not be created.');
		}

		/* Get private key */
		$privatekey = '';

		/* Sets $privatekey by reference */
		$success = openssl_pkey_export($res, $privatekey);

		if ($success === FALSE) {
			show_error('OpenSSL export could not be created.');
		}

		/* Get public key */
		$publickey = openssl_pkey_get_details($res);

		if ($success === FALSE) {
			show_error('OpenSSL details could not be created.');
		}

		/* extract the key */
		$publickey = $publickey['key'];

		/* save them */
		$success = file_put_contents($this->private, $privatekey);

		if ($success === FALSE) {
			show_error('OpenSSL private key could not be created.');
		}

		$success = file_put_contents($this->public, $publickey);

		if ($success === FALSE) {
			show_error('OpenSSL public key could not be created.');
		}
	}

	protected function encode($input) {	
		return ($this->base64) ? strtr(base64_encode($input), ['+' => '.', '=' => '-', '/' => '~']) : $input;
	}

	protected function decode($input) {	
		return ($this->base64) ? base64_decode(strtr($input, ['.' => '+', '-' => '=', '~' => '/'])) : $input;
	}
} /* end class */