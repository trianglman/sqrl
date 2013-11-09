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

namespace trianglman\sqrl\src;

/**
 * Validates a nonce/public key pair
 * 
 * If a database is configured, this will also check to see if the public key
 * matches a previously encountered key. If it does it will load an identifier.
 * If there is no match, it will store the public key and generate an identifier.
 * 
 * @author johnj
 */
class SqrlValidate implements \trianglman\sqrl\interfaces\SqrlValidate{

    protected $_dsn='';
    
    protected $_dbUserName='';
    
    protected $_dbPass='';
    
    protected $_nonceTable='';
    
    protected $_pubKeyTable='';
    
    protected $_sig='';
    
    protected $_nonce='';
    
    protected $nonceIp=0;
    
    protected $_requestorIP=0;
    
    protected $_key='';
    
    protected $_clientVer = 1;
    
    protected $_enforceIP = false;
    
    protected $_db=null;
    
    protected $_validator = null;
    
    protected $signedUrl = '';
    
    protected $_secure=false;
    
    protected $_domain='';
    
    protected $_authPath='';
    
    protected $nonceExpirationDate=null;
    
    public function loadConfigFromJSON($filePath) {
        if(!file_exists($filePath)){throw new \InvalidArgumentException('Configuration file not found');}
        $data = file_get_contents($filePath);
        $decoded = json_decode($data);
        if(is_null($decoded)){throw new \InvalidArgumentException('Configuration data could not be parsed. Is it JSON formatted?');}
        if(!empty($decoded->secure)){
            $this->setSecure($decoded->secure>0);
        }
        if(!empty($decoded->key_domain)){
            $this->setKeyDomain($decoded->key_domain);
        }
        if(!empty($decoded->authentication_path)){
            $this->setAuthenticationPath($decoded->authentication_path);
        }
        if(!empty($decoded->nonce_max_age)){
            $this->setNonceMaxAge($decoded->nonce_max_age);
        }
        if(!empty($decoded->dsn)){
            if(empty($decoded->username)){//sqlite doesn't use usernames and passwords
                $decoded->username = '';
                $decoded->password = '';
            }
            $this->configureDatabase($decoded->dsn, $decoded->username, $decoded->password);
            if(!empty($decoded->nonce_table)){
                $this->setNonceTable($decoded->nonce_table);
            }
            if(!empty($decoded->pubkey_table)){
                $this->setPublicKeyTable($decoded->pubkey_table);
            }
        }
        
    }
    
    public function setNonceMaxAge($minutes)
    {
        if(is_null($minutes)){
            $this->nonceExpirationDate = null;
        }
        else{
            $this->nonceExpirationDate = new \DateTime('-'.$minutes.' Minutes');
        }
    }

    public function setCryptoSignature($signature) {
        $this->_sig = base64_decode(str_replace(array('-','_'), array('+','/'), $signature).'==');
    }

    public function setNonce($nonce) {
        if(!is_null($this->_connectToDatabase())){
            //verify the nonce exists, otherwise we have to trust it was already done
            $sql = 'SELECT created, ip FROM `'.$this->_nonceTable.'` WHERE nonce = ?';
            $stmt = $this->_connectToDatabase()->prepare($sql);
            $stmt->execute(array($nonce));
            $rs = $stmt->fetch(\PDO::FETCH_ASSOC);
            $stmt->fetchAll();//clean up;
            if(empty($rs)){
                throw new SqrlException('Nonce not found',  SqrlException::NONCE_NOT_FOUND);
            }
            if(!is_null($this->nonceExpirationDate)){
                $created = new \DateTime($rs['created']);
                $interval = $this->nonceExpirationDate->diff($created);
                if($interval->format('%r')=='-'){
                    throw new SqrlException('Nonce has expired',  SqrlException::EXPIRED_NONCE);
                }
            }
            $this->setNonceIp($rs['ip']);
        }
        $this->_nonce = $nonce;
    }
    
    public function setNonceIp($ip)
    {
        if(filter_var($ip,FILTER_VALIDATE_INT)){
            $this->nonceIp = (int)$ip;
        }
        else{
            $this->nonceIp = ip2long($ip);
        }
        if($this->nonceIp ===false){
            throw new \InvalidArgumentException('Not a valid IP address.');
        }
    }

    public function setPublicKey($publicKey) {
        $this->_key = base64_decode(str_replace(array('-','_'), array('+','/'), $publicKey).'=');
    }

    public function storePublicKey() {
        if(is_null($this->_connectToDatabase())){
            throw new \RuntimeException('No database connection has been configured.');
        }
        if(empty($this->_pubKeyTable)){
            throw new \RuntimeException('No public key table has been configured.');
        }
        $checkSql = 'SELECT id FROM `'.$this->_pubKeyTable.'` WHERE `public_key` = ?';
        $checkStmt = $this->_connectToDatabase()->prepare($checkSql);
        $checkStmt->execute(array(base64_encode($this->_key)));
        $id = $checkStmt->fetchColumn();
        if($id === false){
            $insertSql = 'INSERT INTO `'.$this->_pubKeyTable.'` (`public_key`) VALUES (?)';
            $insertStmt = $this->_connectToDatabase()->prepare($insertSql);
            $insertStmt->execute(array(base64_encode($this->_key)));
            $id = $this->_connectToDatabase()->lastInsertId();
        }
        return $id;
    }

    public function validate() {
        if(is_null($this->_validator)){throw new \RuntimeException('No validator has been set.');}
        if(empty($this->_sig) || empty($this->_key) || empty($this->_nonce)){return false;}
        $expectedURL = $this->generateUrl($this->_nonce);
        if(substr($this->signedUrl, 0,  strlen($expectedURL)) !== $expectedURL){
            throw new SqrlException('Requested URL doesn\'t match expected URL',SqrlException::SIGNED_URL_DOESNT_MATCH);
        }
        if($this->_enforceIP && $this->nonceIp !== $this->_requestorIP){
            throw new SqrlException('IPs do not match: '.$this->nonceIp.' vs. '.$this->_requestorIP,SqrlException::ENFORCE_IP_FAIL);
        }
        try{
            if(!$this->_validator->validateSignature($this->signedUrl,$this->_sig,$this->_key)){
                throw new SqrlException('Signature not valid.',SqrlException::SIGNATURE_NOT_VALID);
            }
            return true;
        }
        catch(\Exception $e){
            throw new SqrlException('Signature not valid.',SqrlException::SIGNATURE_NOT_VALID);
        }
    }
    
    public function configureDatabase($dsn,$username,$pass)
    {
        $this->_dsn = $dsn;
        $this->_dbUserName = $username;
        $this->_dbPass = $pass;
    }
    
    public function setDatabaseConnection(\PDO $db)
    {
        $this->_db = $db;
    }
    
    public function setPublicKeyTable($table)
    {
        $this->_pubKeyTable = $table;
    }
    
    public function setNonceTable($table)
    {
        $this->_nonceTable = $table;
    }
    
    /**
     * A wrapper function to either get an existing or generate a new database connection
     * 
     * @return \PDO
     */
    protected function _connectToDatabase()
    {
        if(!is_null($this->_db)){
            return $this->_db;
        }
        if(empty($this->_dsn)){
            return null;
        }
        try{
            $this->_db = new \PDO($this->_dsn,$this->_dbUserName,$this->_dbPass);
        } catch (\PDOException $ex) {
            return null;
        }
        return $this->_db;
    }

    public function getPublicKey() {
        if(empty($this->_key)){
            throw new \RuntimeException('No request information has been parsed');
        }
        return $this->_key;
    }

    public function parseSQRLRequest($getParam, $postParam, $headers) {
        if(isset($postParam['sqrlsig'])){
            $this->setCryptoSignature($postParam['sqrlsig']);
        }
        else{throw new SqrlException('No signature was included in the request',  SqrlException::MISSING_SIGNATURE);}
        if(isset($getParam['nut'])){
            $this->setNonce($getParam['nut']);
        }
        else{ throw new SqrlException('No nonce was included in the request',  SqrlException::MISSING_NUT);}
        if(isset($getParam['sqrlkey'])){
            $this->setPublicKey($getParam['sqrlkey']);
        }
        else{throw new SqrlException('No public key was included in the request',  SqrlException::MISSING_PUWK); }
        if(isset($getParam['sqrlver'])){$this->_clientVer = $getParam['sqrlver'];}
        if(isset($getParam['sqrlopt'])){
            $options = explode(',', $getParam['sqrlopt']);
            if(in_array('enforce', $options)){
                $this->_enforceIP = true;
            }
        }
        $isSecureRequest = !empty($headers['HTTPS']);
        $host = $headers['SERVER_NAME'];
        $request = $headers['REQUEST_URI'];
        $qs = $headers[ 'QUERY_STRING' ];
        $this->signedUrl = ($isSecureRequest?'s':'').'qrl://'.$host.$request.'?'.$qs;
        $this->setRequestorIp($headers['REMOTE_ADDR']);
    }

    public function setValidator(\trianglman\sqrl\interfaces\NonceValidator $validator) {
        $this->_validator = $validator;
    }
    
    public function getNonce()
    {
        if(empty($this->_nonce)){
            throw new \RuntimeException('No request information has been parsed');
        }
        return $this->_nonce;
    }

    /**
     * Sets the IP of the user who requested the SQRL image
     * 
     * @param string $ip
     * 
     * @return void
     */
    public function setRequestorIp($ip)
    {
        if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)){throw new \InvalidArgumentException('Not a valid IPv4');}
        $this->_requestorIP = ip2long($ip);
    }

    public function verifyIdentityUnlock() {
        
    }
    
    public function getIdentityLockKey() {
        
    }

    public function getKeyVerifier() {
        
    }

    public function setAuthenticationPath($path) 
    {
        $this->_authPath = $path;
    }

    public function setKeyDomain($domain) {
        $this->_domain = $domain;
    }

    public function setSecure($sec) {
        $this->_secure = (bool)$sec;
    }
    
    protected function generateUrl($nonce)
    {
        $url = ($this->_secure?'s':'').'qrl://'.$this->_domain.(strpos($this->_domain,'/')!==false?'|':'/').$this->_authPath;
        $currentPathParts = parse_url($url);
        if(!empty($currentPathParts['query'])){$pathAppend = '&nut=';}
        else{$pathAppend = '?nut=';}
        return $url.$pathAppend.$nonce;
    }
}
