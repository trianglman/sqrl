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

/**
 * Class to hold configurable data for all other SQRL classes
 *
 * @author luisc
 */
class SqrlConfiguration
{

    /**
     * The versions this SQRL server supports
     * 
     * Defaults to only accepting version 1
     * 
     * @var array[]mixed
     */
    protected $acceptedVersions = array(1);
    /**
     * Whether responses to the server should be secure
     * 
     * Defaults to false
     * 
     * @var boolean
     */
    protected $secure = false;
    /**
     * The domain clients should generate a key for
     * This can include subdirectories of a web domain in order to allow sites managed
     * by subdirectories to use different SQRL keying material for the same user
     * 
     * Required if generating the SQRL URLs and validating responses
     * 
     * @var string
     */
    protected $domain = '';
    /**
     * Path to the authentication script
     * This is appended to the $domain value when generating SQRL URLs
     * 
     * Required if generating SQRL URLs and validating responses
     * 
     * @var string
     */
    protected $authenticationPath = '';
    /**
     * The friendly name displayed to SQRL clients during authentication
     * 
     * Required
     * 
     * @var string
     */
    protected $friendlyName = '';
    /**
     * Whether users are allowed to generate anonymous accounts
     * 
     * If a user with an unrecognized identification key attempts to authenticate,
     * should the site accept just the key as a user identification
     * 
     * Defaults to false
     * 
     * @var boolean
     */
    protected $anonAllowed = false;
    /**
     * Time in minutes that a nonce is considered valid
     * 
     * Default 5
     * 
     * @var int
     */
    protected $nonceMaxAge = 5;
    /**
     * Height, in pixels, of a generated QR code
     * 
     * Default 300
     * 
     * @var int
     */
    protected $qrHeight = 300;
    /**
     * Padding, in pixels, around a generated QR code
     * 
     * Default 10
     * 
     * @var int
     */
    protected $qrPadding = 10;
    /**
     * Random string used to salt generated nonces
     * 
     * @var string
     */
    protected $nonceSalt = 'random data';
    
    /**
     * Loads the configuration from the supplied file path
     * 
     * @param string $filePath The file to load
     * 
     * @throws \InvalidArgumentException If the file can not be parsed
     */
    public function load($filePath)
    {
        try {
            $this->loadConfigFromJSON($filePath);
        } catch (\Exception $ex) {
            throw new \InvalidArgumentException('Configuration data could not be parsed.',1,$ex);
        }
    }

    protected function loadConfigFromJSON($filePath)
    {
        if (!file_exists($filePath)) {
            throw new \InvalidArgumentException('Configuration file not found');
        }
        $data = file_get_contents($filePath);
        $decoded = json_decode($data);
        if (is_null($decoded)) {
            throw new \InvalidArgumentException('Configuration data could not be parsed. Is it JSON formatted?');
        }
        if (is_array($decoded->accepted_versions)) {
            $this->setAcceptedVersions($decoded->accepted_versions);
        }
        $this->setSecure(!empty($decoded->secure) && (int)$decoded->secure>0);
        $this->setDomain(!empty($decoded->key_domain)?$decoded->key_domain:'');
        $this->setAuthenticationPath(
                !empty($decoded->authentication_path)?$decoded->authentication_path:''
                );
        $this->setFriendlyName(!empty($decoded->friendly_name)?$decoded->friendly_name:'');
        $this->setAnonAllowed(
                !empty($decoded->allow_anonymous_accounts) && (int)$decoded->allow_anonymous_accounts>0
                );
        if (!empty($decoded->nonce_max_age)) {
            $this->setNonceMaxAge($decoded->nonce_max_age);
        }
        if (!empty($decoded->height)) {
            $this->setQrHeight($decoded->height);
        }
        if (!empty($decoded->padding)) {
            $this->setQrPadding($decoded->padding);
        }
        $this->setNonceSalt(!empty($decoded->nonce_salt)?$decoded->nonce_salt:'');
    }
    
    /**
     * Gets the versions this SQRL server supports
     * 
     * @return array
     */
    public function getAcceptedVersions() {
        return $this->acceptedVersions;
    }

    /**
     * Gets whether responses to the server should be secure
     * 
     * @return boolean
     */
    public function getSecure() {
        return $this->secure;
    }

    /**
     * Gets the domain clients should generate a key for
     * 
     * @return string
     */
    public function getDomain() {
        return $this->domain;
    }

    /**
     * Gets the path to the authentication script
     * 
     * @return string
     */
    public function getAuthenticationPath() {
        return $this->authenticationPath;
    }

    /**
     * Gets the friendly name displayed to SQRL clients during authentication
     * @return string
     */
    public function getFriendlyName() {
        return $this->friendlyName;
    }

    /**
     * Gets whether users are allowed to generate anonymous accounts
     * 
     * @return boolean
     */
    public function getAnonAllowed() {
        return $this->anonAllowed;
    }

    /**
     * Gets the time in minutes that a nonce is considered valid
     * @return int
     */
    public function getNonceMaxAge() {
        return $this->nonceMaxAge;
    }

    /**
     * Gets the height, in pixels, of a generated QR code
     * 
     * @return int
     */
    public function getQrHeight() {
        return $this->qrHeight;
    }

    /**
     * Gets the padding, in pixels, around a generated QR code
     * 
     * @return int
     */
    public function getQrPadding() {
        return $this->qrPadding;
    }

    /**
     * Gets the random string used to salt generated nonces
     * @return string
     */
    public function getNonceSalt() {
        return $this->nonceSalt;
    }

    /**
     * Sets the versions this SQRL server supports
     * 
     * @param mixed $acceptedVersions
     * 
     * @return SqrlConfiguration
     */
    public function setAcceptedVersions($acceptedVersions) {
        if (is_array($acceptedVersions)) {
            $this->acceptedVersions = $acceptedVersions;
        } else {
            $this->acceptedVersions = array($acceptedVersions);
        }
        return $this;
    }

    /**
     * Sets whether responses to the server should be secure
     * 
     * @param boolean $secure
     * 
     * @return SqrlConfiguration
     */
    public function setSecure($secure) {
        $this->secure = (bool)$secure;
        return $this;
    }

    /**
     * Sets the domain clients should generate a key for
     * 
     * @param string $domain
     * 
     * @return SqrlConfiguration
     */
    public function setDomain($domain) {
        $this->domain = $domain;
        return $this;
    }

    /**
     * Sets the path to the authentication script
     * 
     * @param string $authenticationPath
     * 
     * @return SqrlConfiguration
     */
    public function setAuthenticationPath($authenticationPath) {
        $this->authenticationPath = $authenticationPath;
        return $this;
    }

    /**
     * Sets the friendly name displayed to SQRL clients during authentication
     * 
     * @param string $friendlyName
     * 
     * @return SqrlConfiguration
     */
    public function setFriendlyName($friendlyName) {
        $this->friendlyName = $friendlyName;
        return $this;
    }

    /**
     * Sets whether users are allowed to generate anonymous accounts
     * 
     * @param boolean $anonAllowed
     * 
     * @return SqrlConfiguration
     */
    public function setAnonAllowed($anonAllowed) {
        $this->anonAllowed = (bool)$anonAllowed;
        return $this;
    }

    /**
     * Sets the time in minutes that a nonce is considered valid
     * 
     * @param int $nonceMaxAge
     * 
     * @return SqrlConfiguration
     */
    public function setNonceMaxAge($nonceMaxAge) {
        $this->nonceMaxAge = (int)$nonceMaxAge;
        return $this;
    }

    /**
     * Sets the height, in pixels, of a generated QR code
     * 
     * @param int $qrHeight
     * 
     * @return SqrlConfiguration
     */
    public function setQrHeight($qrHeight) {
        $this->qrHeight = (int)$qrHeight;
        return $this;
    }

    /**
     * Sets the padding, in pixels, around a generated QR code
     * 
     * @param int $qrPadding
     * 
     * @return SqrlConfiguration
     */
    public function setQrPadding($qrPadding) {
        $this->qrPadding = $qrPadding;
        return $this;
    }

    /**
     * Sets the random string used to salt generated nonces
     * 
     * @param string $nonceSalt
     * 
     * @return SqrlConfiguration
     */
    public function setNonceSalt($nonceSalt) {
        $this->nonceSalt = $nonceSalt;
        return $this;
    }

}