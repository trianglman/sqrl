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
     * Dependencies
     */
    /**
     * @var SqrlStoreInterface
     */
    protected $store = null;

    /**
     * @var NonceValidatorInterface
     */
    protected $validator = null;

    /**
     * Server information
     */
    /**
     * The versions of SQRL this server accepts
     * Should be a comma separated list
     * 
     * @var string
     */
    protected $versions = '';
    /**
     * Whether the requests should be secure
     * 
     * @var boolean
     */
    protected $secure = false;

    /**
     * Site domain for the requests
     * 
     * @var string
     */
    protected $domain = '';

    /**
     * path to the authentication script
     * 
     * @var string
     */
    protected $authPath = '';
    
    /**
     * The configured server friendly name
     * 
     * @var string
     */
    protected $sfn = '';

    /**
     * The oldest a nonce can be before being considered expired
     * 
     * @var \DateTime
     */
    protected $nonceExpirationDate = null;

    /**
     * Local nonce inromation
     */
    /**
     * 
     * @var string
     */
    protected $nonce = '';
    
    /**
     * The action the nonce is related to
     * @var int
     */
    protected $nonceAction = -1;
    
    /**
     * The ask associated with the nonce
     * @var string
     */
    protected $nonceAsk = '';
    
    /**
     * the qry associated with a nonce
     * @var string
     */
    protected $nonceQry = '';
    
    /**
     * the lnk associated with a nonce
     * @var string
     */
    protected $nonceLnk = '';

    /**
     * The IP that was originally sent the nonce
     * @var int
     */
    protected $nonceIp = 0;
    
    /**
     * The key the nonce was created for
     * This is only relevant on second loop requests
     * 
     * @var string
     */
    protected $nonceIdk = '';

    /**
     * Request information
     */
    /**
     * @var int
     */
    protected $clientVer = 1;

    /**
     * @var string
     */
    protected $signedServerData = '';

    /**
     * @var string
     */
    protected $clientVal = '';

    /**
     * @var string
     */
    protected $ids = '';

    /**
     * @var string
     */
    protected $idk = '';

    /**
     * @var boolean
     */
    protected $enforceIP = true;

    /**
     * the current requestor's IP
     * @var int
     */
    protected $requestorIP = 0;

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
        if (!empty($decoded->nonce_max_age)) {
            $this->setNonceMaxAge($decoded->nonce_max_age);
        }
        if (!empty($decoded->accepted_versions)) {
            $this->setAcceptedVersions($decoded->accepted_versions);
        }
        if (!empty($decoded->friendly_name)) {
            $this->setFriendlyName($decoded->friendly_name);
        }
    }

    public function setStorage(SqrlStoreInterface $storage)
    {
        $this->store = $storage;
    }

    public function setValidator(NonceValidatorInterface $validator)
    {
        $this->validator = $validator;
    }

    public function setNonceMaxAge($minutes)
    {
        if (is_null($minutes)) {
            $this->nonceExpirationDate = null;
        } else {
            $this->nonceExpirationDate = new \DateTime('-'.$minutes.' Minutes');
        }
    }

    public function setAuthenticationPath($path)
    {
        $this->authPath = $path;
    }

    public function setKeyDomain($domain)
    {
        $this->domain = $domain;
    }

    public function setSecure($sec)
    {
        $this->secure = (bool) $sec;
    }
    
    public function setAcceptedVersions($ver)
    {
        if (is_array($ver)) {
            $this->versions = implode(',',$ver);
        } else {
            $this->version = $ver;
        }
    }
    
    public function setFriendlyName($sfn)
    {
        $this->sfn = $sfn;
    }

    /**************************
     *
     * Request parameters
     *
     **************************/
    public function setSignedServerVal($val)
    {
        $this->signedServerData = $val;
    }

    public function setSignedClientVal($val)
    {
        $this->clientVal = $val;
    }

    public function setClientVer($version)
    {
        $this->clientVer = $version;
    }

    public function setAuthenticateKey($publicKey)
    {
        $this->idk = $publicKey;
    }

    public function setAuthenticateSignature($signature)
    {
        $this->ids = $signature;
    }

    public function setEnforceIP($bool)
    {
        $this->enforceIP = $bool;
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
        $this->requestorIP = ip2long($ip);
    }

    /**************************
     *
     * Nonce parameters
     *
     **************************/
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
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
            $this->setNonceAction($nonceData['action']);
            $this->setNonceIdk($nonceData['related_public_key']);
        }
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

    public function setNonceAction($action)
    {
        $this->nonceAction = (int)$action;
    }

    public function setNonceIdk($key)
    {
        $this->nonceIdk = $key;
    }

    /**
     * Verifies that the server data sent back by the requestor matches
     * the data that was originally sent with the nonce
     * 
     * @param int $requestType The request type the nut is claimed to be sent for
     * @param boolean $https Whether the request was secure
     * @param string|array $serverData The server= information sent by the client
     * 
     * @return boolean
     */
    public function matchServerData($requestType,$https,$serverData)
    {
        if(empty($this->nonce) || empty($this->signedServerData))
        if (($this->secure !== (bool)$https)) {
            return false;
        }
        if (is_array($serverData)) {
            if(empty($serverData['ver']) || $this->versions !== $serverData['ver']) {
                return false;
            }
            if (empty($serverData['tif']) || $this->nonceAction !== $serverData['tif']) {
                return false;
            }
            if (empty($serverData['sfn']) || $this->sfn !== $serverData['sfn']) {
                return false;
            }
            if (!empty($this->nonceLnk) && 
                (empty($serverData['lnk']) || $this->nonceLnk !== $serverData['lnk'])) {
                return false;
            }
            if (!empty($this->nonceQry) && 
                (empty($serverData['qry']) || $this->nonceQry !== $serverData['qry'])) {
                return false;
            }
            if (!empty($this->nonceAsk) && 
                (empty($serverData['ask']) || $this->nonceAsk !== $serverData['ask'])) {
                return false;
            }
        } else {
            $expectedURL = $this->generateUrl($this->nonce);
            if ($serverData !== $expectedURL) {
                return false;
            }
        }
        return true;
    }

    public function validate()
    {
        if (is_null($this->validator)) {
            throw new \RuntimeException('No validator has been set.');
        }
        if (empty($this->ids) || empty($this->idk) || empty($this->signedServerData) || empty($this->clientVal)) {
            throw new \RuntimeException('No signature validation information has been set');
        }
        if ($this->enforceIP && $this->nonceIp !== $this->requestorIP) {
            throw new SqrlException('IPs do not match: '.$this->nonceIp.' vs. '.$this->requestorIP, SqrlException::ENFORCE_IP_FAIL);
        }
        return $this->validateSignature($this->idk, $this->ids);
    }

    public function validateSignature($key, $sig)
    {
        try {
            $signedValue = 'server='.$this->signedServerData.'&client='.$this->clientVal;
            if (!$this->validator->validateSignature($signedValue, $sig, $key)) {
                throw new SqrlException('Signature not valid.', SqrlException::SIGNATURE_NOT_VALID);
            }
            return true;
        } catch (\Exception $e) {
            throw new SqrlException('Signature not valid.', SqrlException::SIGNATURE_NOT_VALID, $e);
        }
    }

    protected function generateUrl($nonce)
    {
        $url = ($this->secure ? 's' : '').'qrl://'.$this->domain.(strpos(
                $this->domain,
                '/'
            ) !== false ? '|' : '/').$this->authPath;
        $currentPathParts = parse_url($url);
        if (!empty($currentPathParts['query'])) {
            $pathAppend = '&nut=';
        } else {
            $pathAppend = '?nut=';
        }

        return $url.$pathAppend.$nonce;
    }
    
    public function getPublicKey()
    {
        if (empty($this->idk)) {
            throw new \RuntimeException('No request information has been parsed');
        }

        return $this->idk;
    }

    public function getNonce()
    {
        if (empty($this->nonce)) {
            throw new \RuntimeException('No request information has been parsed');
        }

        return $this->nonce;
    }
}
