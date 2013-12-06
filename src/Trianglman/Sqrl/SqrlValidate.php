<?php
/*
 * The MIT License (MIT)
 * 
 * Copyright (c) 2013 John Judy
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace Trianglman\Sqrl;

use Trianglman\Sqrl\SqrlException;

/**
 * Validates a nonce/public key pair
 *
 * If a database is configured, this will also check to see if the public key
 * matches a previously encountered key. If it does it will load an identifier.
 * If there is no match, it will store the public key and generate an identifier.
 *
 * @author johnj
 */
class SqrlValidate implements SqrlValidateInterface
{
    /**
     * @var SqrlStoreInterface
     */
    protected $store = null;

    /**
     * @var string
     */
    protected $_sig = '';

    /**
     *
     * @var string
     */
    protected $_nonce = '';

    /**
     * @var int
     */
    protected $nonceIp = 0;

    /**
     * @var int
     */
    protected $_requestorIP = 0;

    /**
     * @var string
     */
    protected $_key = '';

    /**
     * @var int
     */
    protected $_clientVer = 1;

    /**
     * @var boolean
     */
    protected $_enforceIP = false;

    /**
     * @var NonceValidatorInterface
     */
    protected $_validator = null;

    /**
     * @var string
     */
    protected $signedUrl = '';

    /**
     * @var string
     */
    protected $clientVal = '';

    /**
     * @var boolean
     */
    protected $_secure = false;

    /**
     * @var string
     */
    protected $_domain = '';

    /**
     * @var string
     */
    protected $_authPath = '';

    /**
     * @var \DateTime
     */
    protected $nonceExpirationDate = null;

    /**************************
     *
     * Configuration
     *
     **************************/
    public function loadConfigFromJSON($filePath)
    {
        if (!file_exists($filePath)) {
            throw new \InvalidArgumentException('Configuration file not found');
        }
        $data = file_get_contents($filePath);
        $decoded = json_decode($data);
        if (is_null($decoded)) {
            throw new \InvalidArgumentException('Configuration data could not be parsed. Is it JSON formatted?');
        }
        if (!empty($decoded->secure)) {
            $this->setSecure($decoded->secure > 0);
        }
        if (!empty($decoded->key_domain)) {
            $this->setKeyDomain($decoded->key_domain);
        }
        if (!empty($decoded->authentication_path)) {
            $this->setAuthenticationPath($decoded->authentication_path);
        }
        if (!empty($decoded->nonce_max_age)) {
            $this->setNonceMaxAge($decoded->nonce_max_age);
        }
    }

    public function setStorage(SqrlStoreInterface $storage)
    {
        $this->store = $storage;
    }

    public function setNonceMaxAge($minutes)
    {
        if (is_null($minutes)) {
            $this->nonceExpirationDate = null;
        } else {
            $this->nonceExpirationDate = new \DateTime('-'.$minutes.' Minutes');
        }
    }

    public function setValidator(NonceValidatorInterface $validator)
    {
        $this->_validator = $validator;
    }

    public function setAuthenticationPath($path)
    {
        $this->_authPath = $path;
    }

    public function setKeyDomain($domain)
    {
        $this->_domain = $domain;
    }

    public function setSecure($sec)
    {
        $this->_secure = (bool) $sec;
    }

    /**************************
     *
     * Request parameters
     *
     **************************/
    public function setAuthenticateKey($publicKey)
    {
        $this->_key = base64_decode($publicKey);
    }

    public function setAuthenticateSignature($signature)
    {
        $this->_sig = base64_decode($signature);
    }

    public function setSignedUrl($url)
    {
        $this->signedUrl = $url;
    }

    public function setNonce($nonce)
    {
        if (!is_null($this->store)) {
            $nonceData = $this->store->retrieveNutRecord($nonce);
            if (empty($nonceData)) {
                throw new SqrlException('Nonce not found', SqrlException::NONCE_NOT_FOUND);
            }
            if (!is_null($this->nonceExpirationDate)) {
                $created = new \DateTime($nonceData['created']);
                $interval = $this->nonceExpirationDate->diff($created);
                if ($interval->format('%r') == '-') {
                    throw new SqrlException('Nonce has expired', SqrlException::EXPIRED_NONCE);
                }
            }
            $this->setNonceIp($nonceData['ip']);
        }
        $this->_nonce = $nonce;

        return empty($nonceData) ? null : $nonceData['action'];
    }

    public function setClientVer($version)
    {
        $this->_clientVer = $version;
    }

    public function setSignedClientVal($val)
    {
        $this->clientVal = $val;
    }

    public function setEnforceIP($bool)
    {
        $this->_enforceIP = $bool;
    }

    public function setNonceIp($ip)
    {
        if (filter_var($ip, FILTER_VALIDATE_INT)) {
            $this->nonceIp = (int) $ip;
        } else {
            $this->nonceIp = ip2long($ip);
        }
        if ($this->nonceIp === false) {
            throw new \InvalidArgumentException('Not a valid IP address.');
        }
    }

    public function getPublicKey()
    {
        if (empty($this->_key)) {
            throw new \RuntimeException('No request information has been parsed');
        }

        return $this->_key;
    }

    public function getNonce()
    {
        if (empty($this->_nonce)) {
            throw new \RuntimeException('No request information has been parsed');
        }

        return $this->_nonce;
    }

    /**
     * Sets the IP of the user who requested the SQRL image
     *
     * @param string $ip
     *
     * @throws \InvalidArgumentException
     * @return void
     */
    public function setRequestorIp($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new \InvalidArgumentException('Not a valid IPv4');
        }
        $this->_requestorIP = ip2long($ip);
    }

    public function validate()
    {
        if (is_null($this->_validator)) {
            throw new \RuntimeException('No validator has been set.');
        }
        if (empty($this->_sig) || empty($this->_key) || empty($this->_nonce)) {
            return false;
        }
        $expectedURL = $this->generateUrl($this->_nonce);
        if (substr($this->signedUrl, 0, strlen($expectedURL)) !== $expectedURL) {
            throw new SqrlException('Requested URL doesn\'t match expected URL', SqrlException::SIGNED_URL_DOESNT_MATCH);
        }
        if ($this->_enforceIP && $this->nonceIp !== $this->_requestorIP) {
            throw new SqrlException('IPs do not match: '.$this->nonceIp.' vs. '.$this->_requestorIP, SqrlException::ENFORCE_IP_FAIL);
        }
        try {
            $signedValue = 'clientval='.$this->clientVal.'&serverurl='.$this->signedUrl;
            if (!$this->_validator->validateSignature($signedValue, $this->_sig, $this->_key)) {
                throw new SqrlException('Signature not valid.', SqrlException::SIGNATURE_NOT_VALID);
            }

            return true;
        } catch (\Exception $e) {
            throw new SqrlException('Signature not valid.', SqrlException::SIGNATURE_NOT_VALID, $e);
        }
    }

    public function validateSignature($key, $sig)
    {
        try {
            $signedValue = 'clientval='.$this->clientVal.'&serverurl='.$this->signedUrl;
            if (!$this->_validator->validateSignature($signedValue, $sig, $key)) {
                throw new SqrlException('Signature not valid.', SqrlException::SIGNATURE_NOT_VALID);
            }

            return true;
        } catch (\Exception $e) {
            throw new SqrlException('Signature not valid.', SqrlException::SIGNATURE_NOT_VALID, $e);
        }
    }

    protected function generateUrl($nonce)
    {
        $url = ($this->_secure ? 's' : '').'qrl://'.$this->_domain.(strpos(
                $this->_domain,
                '/'
            ) !== false ? '|' : '/').$this->_authPath;
        $currentPathParts = parse_url($url);
        if (!empty($currentPathParts['query'])) {
            $pathAppend = '&nut=';
        } else {
            $pathAppend = '?nut=';
        }

        return $url.$pathAppend.$nonce;
    }
}
