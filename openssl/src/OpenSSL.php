<?php 

	namespace OpenSSL;

	class OpenSSL {

		private $data;
		private $secret;
		private $secret_iv;

		function __construct($data, $pack = "a16::GQS2NTJZe6fBpOAupyS05SpiFD") {

			$ext = function($value) {
				$value = explode('::', $value);
				return $value;
			};
			$pack = $ext($pack);

			$this->secret 		= pack($pack[0], $pack[1]);
			$this->secret_iv 	= pack($pack[0], $pack[1]);

			$this->data = $data;
		}

		private function getData() { return $this->data; }
		private function getSecret() { return $this->secret; }
		private function getSecretIV() { return $this->secret_iv; }

		private static function replace($value) {
			$value = str_replace(" ", "+", $value);
			return $value;
		}

		private static function base64($value, $type = "encode") {
			switch ($type) {
				case 'encode':
					return base64_encode($value);
					break;
				case 'decode':
					return base64_decode($value);
					break;
			}
		}

		public static function encode($value, $pack = "a16::GQS2NTJZe6fBpOAupyS05SpiFD") {
			$ssl = new OpenSSL($value, $pack);

			$encode = openssl_encrypt(
				$ssl->getData(),
				'AES-128-CBC',
				$ssl->getSecret(),
				0,
				$ssl->getSecretIV()
			);

			$encode = OpenSSL::base64($encode);

			return $encode;
		}

		public static function decode($value, $pack = "a16::GQS2NTJZe6fBpOAupyS05SpiFD") {
			$value = OpenSSL::replace($value);
			$value = OpenSSL::base64($value, 'decode');
			
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
