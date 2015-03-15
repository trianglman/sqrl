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
 * An abstract class to help users create and read stateless nuts
 * 
 * Rather than storing the values important to the nut in stateful storage, 
 * the values will be encrypted into the nut.
 *
 * @author johnj
 */
abstract class SqrlStoreStatelessAbstract implements SqrlStoreInterface 
{
    /**
     * The password for the nonce encryption
     * 
     * Using this name to keep it consistent with the stateful 
     * @var string
     */
    private $nonceSalt = '';
    private $iv = 'fdjlask;aowifjnv';
    
    /**
     * Sets the password for nonce encryption
     * 
     * @param string $salt
     * 
     * @return void
     */
    public function setNonceSalt($salt)
    {
        $this->nonceSalt = $salt;
    }
    
    /**
     * Creates a nut from the supplied data
     * 
     * Takes the nut data, compacts it into a usable format with date, 
     * session and random info data, and encrypts it into a usable nut
     * 
     * @param int $tif The action associated with the nut
     * @param string $key The authentication key the nut is for
     * @param string $oldnut The previous nut in this transacion.
     *      Information from this nut will be used to help store the new nut in
     *      the right session.
     * 
     * @return string
     * 
     * @throws \InvalidArgumentException
     */
    public function generateNut($tif=0, $key='', $oldnut='')
    {
        $nut = '';
        $created = dechex(time());//8 char
        $rnd = openssl_random_pseudo_bytes(4);//4 char
        $ip = dechex(ip2long($this->getIp()));//8 char
        $check = 'sqrl';//to make sure it decrypted
        if (!empty($oldnut)) {
            $nutInfo = $this->getNutDetails($oldnut);
            if (is_array($nutInfo)) {
                $sessionId = $nutInfo['sessionId'];//128 char max
            } else {
                throw new \InvalidArgumentException('Old nut was not found.');
            }
        } else {
            $sessionId = $this->getCurrentSessionId();//128 char max
            $sessionData = $this->getSessionInfo($sessionId);
            if (is_array($sessionData) && isset($sessionData['sqrl_nuts'])) {
                $currentNuts = explode(';',$sessionData['sqrl_nuts']);
                return $currentNuts[0];
            }
        }
        $nut = $rnd.$created.$ip.str_pad(dechex($tif), 2, '0', STR_PAD_LEFT).$sessionId.$check;//154 characters
        
        $encNut = $this->base64UrlEncode(openssl_encrypt($nut, 'aes128', $this->nonceSalt,0,$this->iv));
        
        $this->addSessionNut($encNut,$sessionId);
        if (!empty($key) && isset($sessionId)) {
            $this->setSessionValue($sessionId,'sqrl_key', $key);
        }
        
        return $encNut;
    }
    
    /**
     * Retrieves information about the supplied nut
     *
     * @param string $nut    The nonce to retrieve information on
     *
     * @return array:
     *      'tif'=> int The tif stored with the nut (0 for first request nuts)
     *      'originalKey'=> string The key associated with the nut, if any
     *      'originalNut'=> string The nut that came before this one in the transaction, if any
     *      'createdDate'=> \DateTime The time the nut was created
     *      'nutIP'=> string the IP address that requested the nut
     *      'sessionId'=> string the session ID for the nut [this is only required in stateless nuts]
     */
    public function getNutDetails($nut,$debug =false)
    {
        $decNut = openssl_decrypt($this->base64URLDecode($nut), 'aes128', $this->nonceSalt,0,$this->iv);
        if ('sqrl' !== substr($decNut, -4)) {
            return null;//this nut was not encrypted with our key
        }
        $timestamp = hexdec(substr($decNut, 4, 8));
        $ip = long2ip(hexdec(substr($decNut, 12, 8)));
        $tif = hexdec(substr($decNut, 20, 2));
        $sessionId = substr($decNut, 22,strlen($decNut)-26);
        
        $sessionInfo = $this->getSessionInfo($sessionId);
        if (!is_array($sessionInfo)) {
            return null;//there's not a session that matches this nut, either it was lost or never existed
        }
        $currentNuts = isset($sessionInfo['sqrl_nuts'])?explode(';',$sessionInfo['sqrl_nuts']):array();
        if (!in_array($nut,$currentNuts)) {
            return null;//this session never had this nut, somehow...
        }
        if ($currentNuts[count($currentNuts)-1]!==$nut) {
            return null;//someone is trying to resign an older nut
        }
        
        return array(
            'tif'=> $tif,
            'originalKey'=> isset($sessionInfo['sqrl_key'])?$sessionInfo['sqrl_key']:'',
            'originalNut'=> $currentNuts[0],
            'createdDate'=> new \DateTime('@'.$timestamp),
            'nutIP'=> $ip,
            'sessionId'=> $sessionId
        );
    }
    
    /**
     * Adds a nut to the user's current session
     * 
     * @param string $newNut
     * 
     * @return void
     */
    protected function addSessionNut($newNut,$sessionId)
    {
        $sessionInfo = $this->getSessionInfo($sessionId);
        $currentNuts = isset($sessionInfo['sqrl_nuts'])?explode(';',$sessionInfo['sqrl_nuts']):array();
        $currentNuts[] = $newNut;
        $this->setSessionValue($sessionId,'sqrl_nuts', implode(';',$currentNuts));
    }
    
    public function logSessionIn($requestNut)
    {
        $nutInfo = $this->getNutDetails($requestNut);
        if (is_array($nutInfo)) {
            $this->setSessionValue($nutInfo['sessionId'],'sqrl_authenticated', '1');
        }
    }


    /**
     * Gets the session information that matches the supplied session ID
     * 
     * @param string $sessionId
     * 
     * @return array
     */
    protected abstract function getSessionInfo($sessionId);
    
    /**
     * Gets the user's current session ID
     * 
     * @return string
     */
    protected abstract function getCurrentSessionId();
    
    /**
     * Gets the user's IP address
     * 
     * @return string
     */
    protected abstract function getIp();
    
    /**
     * Sets or updates a value in the user session
     * 
     * @param string $sessionId
     * @param string $key
     * @param string $value
     * 
     * @return void
     */
    protected abstract function setSessionValue($sessionId,$key,$value);
    
    /**
     * Base 64 URL encodes a string
     * 
     * Basically the same as base64 encoding, but replacing "+" with "-" and 
     * "/" with "_" to make it safe to include in a URL
     * 
     * Optionally removes trailing "=" padding characters.
     * 
     * @param string $string The string to encode
     * @param type $stripEquals [Optional] Whether to strip the "=" off of the end
     * 
     * @return string
     */
    protected function base64UrlEncode($string, $stripEquals=true)
    {
        $base64 = base64_encode($string);
        $urlencode = str_replace(array('+','/'), array('-','_'), $base64);
        if($stripEquals){
            $urlencode = trim($urlencode, '=');
        }
        return $urlencode;
    }
    
    /**
     * Base 64 URL decodes a string
     * 
     * Basically the same as base64 decoding, but replacing URL safe "-" with "+"
     * and "_" with "/". Automatically detects if the trailing "=" padding has
     * been removed.
     * 
     * @param type $string
     * @return type
     */
    protected function base64URLDecode($string)
    {
        $len = strlen($string);
        if($len%4 > 0){
            $string = str_pad($string, 4-($len%4), '=');
        }
        $base64 = str_replace(array('-','_'), array('+','/'), $string);
        return base64_decode($base64);
    }
}
