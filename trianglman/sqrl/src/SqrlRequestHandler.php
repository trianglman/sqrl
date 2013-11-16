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
    
    public function __construct(\trianglman\sqrl\interfaces\SqrlValidate $val)
    {
        $this->validator = $val;
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
            $this->validator->setAuthenticateKey(str_replace(array('-','_'), array('+','/'),$clientVal['authkey']).'=');
        }
        else{
            $this->message = 'No public key was included in the request'; 
            return;
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
            if($this->validator->validate()){
                $this->message = "Successfully authenticated.";
            }
            if($this->requestType!= self::AUTHENTICATION_REQUEST){
                //handle other "verbs"
            }
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
