<?php 

	namespace OpenSSL;

	class OpenSSL {

		private $data;
		private $secret;
		private $secret_iv;

		function __construct($data, $pack = "a16::senha") {

			$ext = function($value) {
				$value = explode('::', $value);
				return $value;
			};
			$pack = $ext($pack);

			$this->secret 		= pack($pack[0], $pack[1]);
			$this->secret_iv 	= pack($pack[0], $pack[1]);

			$this->data = $data;
		}

		public function getData() { return $this->data; }
		public function getSecret() { return $this->secret; }
		public function getSecretIV() { return $this->secret_iv; }

		public static function encode($value, $pack = "a16::senha") {
			$ssl = new OpenSSL($value, $pack);

			$encode = openssl_encrypt(
				$ssl->getData(),
				'AES-128-CBC',
				$ssl->getSecret(),
				0,
				$ssl->getSecretIV()
			);

			return $encode;
		}

		public static function decode($value, $pack = "a16::senha") {
			$ssl = new OpenSSL($value, $pack);

			$decode = openssl_decrypt(
				$ssl->getData(),
				'AES-128-CBC',
				$ssl->getSecret(),
				0,
				$ssl->getSecretIV()
			);

			return $decode;
		}

	}

?>