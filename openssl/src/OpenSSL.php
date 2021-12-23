<?php

namespace OpenSSL;

/**
 * OpenSSL
 */
class OpenSSL
{

    /**
     * data
     *
     * @var mixed
     */
    private $data;
    /**
     * secret
     *
     * @var mixed
     */
    private $secret;
    /**
     * secret_iv
     *
     * @var mixed
     */
    private $secret_iv;

    /**
     * __construct
     *
     * @param  mixed $data
     * @param  mixed $pack
     * @return void
     */
    function __construct($data, $pack = "a16::GQS2NTJZe6fBpOAupyS05SpiFD")
    {

        $ext = function ($value) {
            $value = explode('::', $value);
            return $value;
        };
        $pack = $ext($pack);

        $this->secret         = pack($pack[0], $pack[1]);
        $this->secret_iv     = pack($pack[0], $pack[1]);

        $this->data = $data;
    }

    /**
     * getData
     *
     * @return string
     */
    public function getData()
    {
        return $this->data;
    }
    /**
     * getSecret
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }
    /**
     * getSecretIV
     *
     * @return string
     */
    public function getSecretIV()
    {
        return $this->secret_iv;
    }

    /**
     * replace
     *
     * @param  string $value
     * @return array
     */
    private static function replace($value)
    {
        $value = str_replace(" ", "+", $value);
        return $value;
    }

    /**
     * base64
     *
     * @param  mixed $value
     * @param  mixed $type
     * @return void
     */
    private static function base64($value, $type = "encode")
    {
        switch ($type) {
            case 'encode':
                return base64_encode($value);
                break;
            case 'decode':
                return base64_decode($value);
                break;
        }
    }

    /**
     * encode
     *
     * @param  mixed $value
     * @param  mixed $pack
     * @return void
     */
    public static function encode($value, $pack = "a16::GQS2NTJZe6fBpOAupyS05SpiFD")
    {
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

    /**
     * decode
     *
     * @param  mixed $value
     * @param  mixed $pack
     * @return void
     */
    public static function decode($value, $pack = "a16::GQS2NTJZe6fBpOAupyS05SpiFD")
    {
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
