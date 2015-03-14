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
     * @var NonceValidatorInterface
     */
    protected $validator = null;
    
    /**
     *
     * @var SqrlConfiguration
     */
    protected $configuration = null;

    /**
     * 
     * @param \Trianglman\Sqrl\SqrlConfiguration $config
     * @param \Trianglman\Sqrl\NonceValidatorInterface $validator
     * @param \Trianglman\Sqrl\SqrlStoreInterface $storage
     */
    public function __construct(SqrlConfiguration $config, NonceValidatorInterface $validator, SqrlStoreInterface $storage)
    {
        $this->configuration = $config;
        $this->validator = $validator;
        $this->store = $storage;
    }

    /**
     * Validates the returned server value
     * 
     * @param string $server The returned server value
     * @param string $nut The nut from the request
     * @param string $secure Whether the request was secure
     * 
     * @return boolean
     */
    public function validateServer($server,$nut,$secure)
    {
        if (is_string($server)) {
            return $server === $this->getUrl($nut) &&
                    !!$secure===$this->configuration->getSecure();
        } else {
            if (!isset($server['ver']) ||
                    !isset($server['nut']) ||
                    !isset($server['tif']) ||
                    !isset($server['qry']) ||
                    !isset($server['sfn']) 
                    ) {
                return false;
            }
            $nutInfo = $this->store->getNutDetails($nut);
            return $server['ver']===implode(',',$this->configuration->getAcceptedVersions()) &&
                    $server['nut']===$nut &&
                    (!is_array($nutInfo) || hexdec($server['tif'])===$nutInfo['tif']) &&
                    $server['qry'] === $this->generateQry($nut) &&
                    $server['sfn'] === $this->configuration->getFriendlyName() &&
                    !!$secure===$this->configuration->getSecure();
        }
    }
    
    /**
     * Validates a supplied nut
     * 
     * @param string $nut
     * 
     * @return int One of the nut class constants
     */
    public function validateNut($nut)
    {
        $nutInfo = $this->store->getNutDetails($nut);
        if (!is_array($nutInfo)) {
            return self::INVALID_NUT;
        } elseif ($nutInfo['createdDate']->format('U') > strtotime('-'.$this->configuration->getNonceMaxAge().' minutes')) {
            return self::VALID_NUT;
        } else {
            return self::EXPIRED_NUT;
        }
    }

    /**
     * Validates a secondary request signature (Unlock Request or New Key)
     *
     * @param string $orig
     * @param string $key 
     * @param string $sig 
     *
     * @return boolean
     */
    public function validateSignature($orig,$key, $sig)
    {
        return $this->validator->validateSignature($orig, $sig, $key);
    }
    
    /**
     * Verifies the original nut's IP matches the current IP
     * 
     * @param string $nut
     * @param string $ip
     * 
     * @return boolean
     */
    public function nutIPMatches($nut,$ip)
    {
        $nutInfo = $this->store->getNutDetails($nut);
        return is_array($nutInfo) && $nutInfo['nutIP'] === $ip;
    }
    
    /**
     * This should eventually become a trait and share the functionality with SqrlGenerate
     * instead of being duplicate code
     * 
     * @return string
     */
    protected function generateQry($nut)
    {
        $currentPathParts = parse_url($this->configuration->getAuthenticationPath());
        $pathAppend = (empty($currentPathParts['query'])?'?':'&').'nut=';

        return $this->configuration->getAuthenticationPath().$pathAppend.$nut;
    }

    /**
     * This should eventually become a trait and share the functionality with SqrlGenerate
     * instead of being duplicate code
     * 
     * @return string
     */
    protected function getUrl($nut)
    {
        return ($this->configuration->getSecure() ? 's' : '').'qrl://'
                .$this->configuration->getDomain()
                .(strpos($this->configuration->getDomain(),'/') !== false ? '|' : '/')
                .$this->generateQry($nut);
    }
}
