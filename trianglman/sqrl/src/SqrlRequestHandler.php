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
 * A handler to process the authentication of SQRL clients
 * 
 * This class will process a request, send it to the validator, then depending on
 * the type of request, send a success message, send an error message, or send a
 * request for more information (e.g. initiate the second loop to create a new user)
 *
 * @author johnj
 */
class SqrlRequestHandler implements \trianglman\sqrl\interfaces\SqrlRequestHandler{
    
    /**
     *
     * @var \trianglman\sqrl\interfaces\SqrlValidate
     */
    protected $validator=null;
    
    /**
     *
     * @var string
     */
    protected $message = '';
    
    /**
     *
     * @var string
     */
    protected $requestType = self::AUTHENTICATION_REQUEST;
    
    /**
     *
     * @var int
     */
    protected $responseCode = 200;
    
    /**
     *
     * @var int
     */
    protected $clientVer=1;
    
    /**
     * Base 64 encoded authentication key
     * @var string
     */
    protected $authenticateKey = '';
    
    /**
     * Base 64 encoded server unlock key
     * @var string
     */
    protected $serverUnlockKey = '';
    
    /**
     * Base 64 verify unlock key
     * @var string
     */
    protected $verifyUnlockKey = '';
    
    /**
     * Base 64 unlock request signing key
     * @var string
     */
    protected $unlockRequestKey = '';
    
    /**
     * Base 64 signature using the unlock request key
     * @var string
     */
    protected $unlockRequestSig = '';
    
    /**
     * Base 64 new authentication key
     * @var string
     */
    protected $newKey = '';
    
     /**
     * Base 64 signature using the new authentication key
     * @var string
     */
    protected $newKeySig = '';
    
   /**
     *
     * @var \trianglman\sqrl\interfaces\SqrlGenerate
     */
    protected $sqrlGenerator = null;
    
    /**
     *
     * @var \trianglman\sqrl\interfaces\SqrlStore
     */
    protected $store = null;
    
    public function __construct(\trianglman\sqrl\interfaces\SqrlValidate $val,
            \trianglman\sqrl\interfaces\SqrlStore $store=null,
            \trianglman\sqrl\interfaces\SqrlGenerate $gen=null)
    {
        $this->validator = $val;
        $this->sqrlGenerator = $gen;
        $this->store = $store;
    }
    
    /**
     * Parses a user request
     * 
     * This will determine what type of request is being performed and set values
     * up for use in validation and creating the response.
     * 
     * @param array $get The user's GET request
     * @param array $post The user's POST body
     * @param array $server Server level variables (the _SERVER array)
     * 
     * @return void
     */
    public function parseRequest($get,$post,$server)
    {
       if(isset($post['clientval'])){
            $clientVal = array();
            parse_str($post['clientval'], $clientVal);
            $this->validator->setSignedClientVal($post['clientval']);
        }
        else{
            $this->message = 'No client response was included in the request';
            return;
        }
        if(isset($clientVal['ver'])){
            $this->clientVer = $clientVal['ver'];
            $this->validator->setClientVer($clientVal['ver']);
        }
        else{
            $this->message = 'No version was included in the request';
            return;
        }
        if(isset($get['nut'])){
            try{
                $reqType = $this->validator->setNonce($get['nut']);
                //overwrite the request type with the nonce's request type if the 
                //default hasn't been overwritten and a request type was found
                if($this->requestType == self::AUTHENTICATION_REQUEST && $reqType!=null){
                    $this->requestType = $reqType;
                }
            }
            catch(SqrlException $e){
                if($e->getCode() == SqrlException::NONCE_NOT_FOUND){
                    $this->message = 'No nonce was included in the request';//do we want to be more explicit?
                }
                elseif($e->getCode() == SqrlException::EXPIRED_NONCE){
                    $this->message = 'No nonce was included in the request';//do we want to be more explicit?
                }
                else{
                    //no other SQRL related exceptions should happen, but if a 
                    //user extends the validator and exception class, it may happen.
                    //Let the user handle it.
                    throw $e;
                }
                return;
            }
        }
        else{
            $this->message = 'No nonce was included in the request';
            return;
        }
        if(isset($clientVal['opt'])){
            $options = explode(' ', $clientVal['opt']);
            if(in_array('enforce', $options)){
                $this->validator->setEnforceIP(true);
            }
            if(in_array('disable',$options)){
                $this->requestType = self::DISABLE_REQUEST;
            }
            if(in_array('rekey',$options)){
                $this->requestType = self::REKEY_REQUEST;
            }
        }
        if(isset($clientVal['authkey'])){
            $this->authenticateKey = str_replace(array('-','_'), array('+','/'),$clientVal['authkey']).'=';
            $this->validator->setAuthenticateKey($this->authenticateKey);
        }
        else{
            $this->message = 'No public key was included in the request'; 
            return;
        }
        if($this->requestType == self::NEW_ACCOUNT_REQUEST){
            if(isset($clientVal['suk'])){
                $this->serverUnlockKey = str_replace(array('-','_'), array('+','/'),$clientVal['suk']).'=';
            }
            else{
                $this->message = 'No server unlock key was included in the request';
                return;
            }
            if(isset($clientVal['vuk'])){
                $this->verifyUnlockKey = str_replace(array('-','_'), array('+','/'),$clientVal['vuk']).'=';
            }
            else{
                $this->message = 'No verify unlock key was included in the request';
                return;
            }
        }
        if($this->requestType == self::REKEY_REQUEST_LOOP2){
            if(isset($clientVal['urskey'])){
                $this->unlockRequestKey = str_replace(array('-','_'), array('+','/'),$clientVal['urskey']).'=';
            }
            else{
                $this->message = 'No unlock request signing key was included in the request';
                return;
            }
            if(isset($post['urssig'])){
                $this->unlockRequestSig = str_replace(array('-','_'), array('+','/'), $post['urssig']).'==';
            }
            else{
                $this->message = 'No signature was included in the request';
                return;
            }
            $this->requestType = self::REENABLE_REQUEST;
            if(isset($clientVal['newkey'])){
                $this->newKey = str_replace(array('-','_'), array('+','/'),$clientVal['newkey']).'=';
                $this->requestType = self::MIGRATE_REQUEST;
                if(isset($post['newkeysig'])){
                    $this->newKeySig = str_replace(array('-','_'), array('+','/'), $post['newkeysig']).'==';
                }
                else{
                    $this->message = 'No signature was included in the request';
                    return;
                }
            }
            else{
                $this->newKey = $this->authenticateKey;
            }
            if(isset($clientVal['vuk']) && isset($clientVal['suk'])){
                $this->serverUnlockKey = str_replace(array('-','_'), array('+','/'),$clientVal['suk']).'=';
                $this->verifyUnlockKey = str_replace(array('-','_'), array('+','/'),$clientVal['vuk']).'=';
                $this->requestType = $this->requestType==self::MIGRATE_REQUEST?
                        self::REPLACE_REQUEST:
                        self::RELOCK_REQUEST;
            }
        }
        if(isset($post['serverurl'])){
            $this->validator->setSignedUrl($post['serverurl']);
        }
        else{
            $this->message = 'No server URL was included in the request';
            return;
        }
        if(isset($post['authsig'])){
            $this->validator->setAuthenticateSignature(str_replace(array('-','_'), array('+','/'), $post['authsig']).'==');
        }
        else{
            $this->message = 'No signature was included in the request';
            return;
        }
        $this->validator->setRequestorIp($server['REMOTE_ADDR']);
    }
    
    /**
     * Gets the type of request the user made
     * 
     * The return value will be one of the predefined constants
     * 
     * @return int
     */
    public function getRequestType()
    {
        return $this->requestType;
    }
    
    /**
     * Gets the text message to be returned to the SQRL client
     * 
     * @return string
     */
    public function getResponseMessage()
    {
        if(!empty($this->message)){
            return $this->message;
        }
        try {
            $this->verifyRequest();
            if(!is_null($this->store)){
                $this->storeKeyUpdate();
            }
            $this->buildSucessResponse();
        } catch (SqrlException $exc) {
            switch($exc->getCode()){
                case SqrlException::ENFORCE_IP_FAIL:
                    $this->message = "IP check failed.";
                    break;
                case SqrlException::SIGNED_URL_DOESNT_MATCH:
                    $this->message = "The returned URL does not match the initial SQRL challenge.";
                    break;
                case SqrlException::SIGNATURE_NOT_VALID:
                    $this->message = "The signature is not valid.";
                    break;
                default:
                    //no other SQRL related exceptions should happen, but if a 
                    //user extends the validator and exception class, it may happen.
                    //Let the user handle it.
                    throw $exc;
            }
        }
        return $this->message;
        
    }
    
    protected function storeKeyUpdate()
    {
        switch($this->requestType){
            case self::NEW_ACCOUNT_REQUEST:
                $this->store->storeIdentityLock($this->authenticateKey, 
                        $this->serverUnlockKey, 
                        $this->verifyUnlockKey);
                break;
            case self::DISABLE_REQUEST:
                $this->store->lockKey($this->authenticateKey);
                break;
            case self::REENABLE_REQUEST:
            case self::MIGRATE_REQUEST:
                $this->store->migrateKey($this->authenticateKey, $this->newKey);
                break;
            case self::RELOCK_REQUEST:
                $this->store->storeIdentityLock($this->authenticateKey, 
                        $this->serverUnlockKey, 
                        $this->verifyUnlockKey);
                break;
            case self::REPLACE_REQUEST:
                $this->store->migrateKey($this->authenticateKey, $this->newKey,
                        $this->serverUnlockKey,$this->verifyUnlockKey);
        }
    }
    
    protected function verifyRequest()
    {
        $this->validator->validate();
        if($this->requestType!= self::AUTHENTICATION_REQUEST){
            $idLockReqs = array(self::REENABLE_REQUEST,self::RELOCK_REQUEST,
                self::MIGRATE_REQUEST,self::REPLACE_REQUEST);
            if(in_array($this->requestType,$idLockReqs)){
                $this->validator->validateSignature($this->unlockRequestKey,
                        $this->unlockRequestSig);
                if($this->newKey!=$this->authenticateKey){
                    $this->validator->validateSignature($this->newKey,
                            $this->newKeySig);
                }
            }
        }
    }
    
    protected function buildSucessResponse()
    {
        switch($this->requestType){
            case self::AUTHENTICATION_REQUEST:
                $this->message = "Successfully authenticated.";
                if(!is_null($this->store)){
                    $check = $this->store->retrieveAuthenticationRecord($this->authenticateKey, SqrlStore::ID);
                    var_dump($check);
                    if(is_array($check)){
                        $this->message = $this->generateSecondLoop(self::NEW_ACCOUNT_REQUEST);
                    }
                }
                break;
            case self::REKEY_REQUEST:
                $this->message = $this->generateSecondLoop(self::REKEY_REQUEST_LOOP2);
                break;
            case self::NEW_ACCOUNT_REQUEST:
                $this->message = 'New account successfully created.';
                break;
            case self::DISABLE_REQUEST:
                $this->message = 'Account locked.';
                break;
            case self::REENABLE_REQUEST:
                $this->message = 'Account Re-enabled.';
                break;
            case self::MIGRATE_REQUEST:
                $this->message = 'Authentication key migrated.';
                break;
            case self::RELOCK_REQUEST:
                $this->message = 'Identity Lock key migrated.';
                break;
            case self::REPLACE_REQUEST:
                $this->message = 'Authentication keys migrated.';
                break;
        }
    }
    
    protected function generateSecondLoop($loopPurpose)
    {
        if(is_null($this->sqrlGenerator)){
            return 'Second loop required: '
                .($loopPurpose==self::NEW_ACCOUNT_REQUEST?'new account':'re-key');
        }
        $this->sqrlGenerator->getNonce($loopPurpose, $this->authenticateKey);//done to build it
        return $this->sqrlGenerator->getUrl();
    }
    
    /**
     * Gets the numeric HTTP code to return to the SQRL client
     * 
     * Currently the spec only uses the 200 code and any error message is in the
     * test message response
     * 
     * @return int
     */
    public function getResponseCode()
    {
        return $this->responseCode;
    }
    
    /**
     * A helper function to send the response message and code to the SQRL client
     * 
     * @return void
     */
    public function sendResponse()
    {
        
    }
    
}
