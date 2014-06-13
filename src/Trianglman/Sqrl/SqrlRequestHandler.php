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
 * A handler to process the authentication of SQRL clients
 *
 * This class will process a request, send it to the validator, then depending on
 * the type of request, send a success message, send an error message, or send a
 * request for more information (e.g. initiate the second loop to create a new user)
 *
 * @author johnj
 */
class SqrlRequestHandler implements SqrlRequestHandlerInterface
{
    /**
     * @var SqrlValidate
     */
    protected $validator = null;

    /**
     * @var string
     */
    protected $message = '';

    /**
     * @var string
     */
    protected $requestType = self::INITIAL_REQUEST;
    
    /**
     *
     * @var string
     */
    protected $cmd = '';

    /**
     * @var int
     */
    protected $responseCode = 200;

    /**
     * @var int
     */
    protected $clientVer = 1;

    /**
     * Base 64 encoded authentication key
     *
     * @var string
     */
    protected $authenticateKey = '';

    /**
     * Base 64 encoded server unlock key
     *
     * @var string
     */
    protected $serverUnlockKey = '';

    /**
     * Base 64 verify unlock key
     *
     * @var string
     */
    protected $verifyUnlockKey = '';

    /**
     * Base 64 unlock request signing key
     *
     * @var string
     */
    protected $unlockRequestKey = '';

    /**
     * Base 64 signature using the unlock request key
     *
     * @var string
     */
    protected $unlockRequestSig = '';

    /**
     * pIDK (base 64)
     *
     * @var string
     */
    protected $oldKey = '';

    /**
     * Base 64 signature using the new authentication key
     *
     * @var string
     */
    protected $oldKeySig = '';

    /**
     * @var SqrlGenerate
     */
    protected $sqrlGenerator = null;

    protected $acceptedVersions = 1;
    
    protected $sfn = '';

    /**
     *
     * @var SqrlStoreInterface
     */
    protected $store = null;

    public function __construct(
        SqrlValidateInterface $val,
        SqrlStoreInterface $store = null,
        SqrlGenerateInterface $gen = null
    ) {
        $this->validator = $val;
        $this->sqrlGenerator = $gen;
        $this->store = $store;
    }
    
    public function setSfn($sfn)
    {
        $this->sfn = $sfn;
    }

    /**
     * Parses a user request
     *
     * This will determine what type of request is being performed and set values
     * up for use in validation and creating the response.
     *
     * @param array $get    The user's GET request
     * @param array $post   The user's POST body
     * @param array $server Server level variables (the _SERVER array)
     *
     * @throws \Exception
     * @throws SqrlException
     *
     * @return void
     */
    public function parseRequest($get, $post, $server)
    {
        if (isset($post['client'])) {
            $this->validator->setSignedClientVal($post['client']);
            try {
                $this->decodeClientVals($this->base64URLDecode($post['client']));
            } catch (Trianglman\Sqrl\SqrlException $e) {
                if ($e->getCode() === SqrlException::INVALID_REQUEST) {
                    $this->message = $this->formatResponse(
                        $e->getMessage(),
                        self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE,
                        false
                    );
                    return;
                } else {
                    throw $e;
                }
            }
        } else {
            $this->message = $this->formatResponse(
                'No client response was included in the request',
                self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE,
                false
            );
            return;
        }
        if (isset($post['server'])) {
            $this->validator->setSignedServerVal($post['server']);
            try{
                $this->decodeServerData($this->base64URLDecode($post['server']),$get,$server);
            } catch (SqrlException $e) {
                //what exceptions can be caused?
                $this->message = $this->formatResponse(
                    $e->getMessage(), 
                    self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE,
                    false
                );
            }
        } else {
            $this->message = $this->formatResponse(
                'No server data was included in the request', 
                self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE,
                false
            );
            return;
        }
        if (isset($post['ids'])) {
            $this->validator->setAuthenticateSignature($this->base64URLDecode($post['ids']));
        } else {
            $this->message = $this->formatResponse(
                'No identity signature was included in the request', 
                self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE,
                false
            );
            return;
        }
        if (isset($post['pids'])) {
            $this->oldKeySig = $post['pids'];
            //set up validator, or call it multiple times?
        } elseif (!empty($this->oldKey)) {
            $this->message = $this->formatResponse(
                'No previous identity signature was included in the request, but previous identity key was', 
                self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE,
                false
            );
            return;
        }
        if (isset($post['urs'])) {
            $this->$unlockRequestSig = $post['urs'];
            //set up validator, or call it multiple times?
        } elseif (in_array($this->cmd, array('setkey','setlock','enable','delete'))) {
            $this->message = $this->formatResponse(
                'Command requires a matching verify unlock key and unlock request signature. No signature was provided', 
                self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE,
                false
            );
            return;
        }
        $this->validator->setRequestorIp($server['REMOTE_ADDR']);
    }
    
    /**
     * Takes a (base64Url decoded) client value string and breaks it into its individual values
     * @param string $clientInput
     * @return void
     */
    protected function decodeClientVals($clientInput)
    {
        $inputAsArray = explode("\n", $clientInput);
        foreach ($inputAsArray as $individualInputs) {
            list($key,$val) = explode("=", $individualInputs);
            $val = trim($val);//strip off the \r
            switch ($key){
                case 'ver':
                    $this->clientVer = $val;
                    $this->validator->setClientVer($val);
                    break;
                case 'cmd':
                    $this->cmd = $val;
                    break;
                case 'val':
                    //do ask parameter stuff
                    break;
                case 'idk':
                    $this->authenticateKey = $this->base64URLDecode($val);
                    $this->validator->setAuthenticateKey($this->base64URLDecode($val));
                    break;
                case 'pidk':
                    $this->oldKey = $this->base64URLDecode($val);
                    break;
                case 'suk':
                    $this->serverUnlockKey = $this->base64URLDecode($val);
                    break;
                case 'vuk':
                    $this->verifyUnlockKey = $this->base64URLDecode($val);
                    break;
            }
        }
        if(empty($this->clientVer)){
            throw new SqrlException(
                'No version was included in the request', 
                SqrlException::INVALID_REQUEST
            );
        }
        if(empty($this->authenticateKey)){
            throw new SqrlException(
                'No idk was included in the request', 
                SqrlException::INVALID_REQUEST
            );
        }
        if(empty($this->cmd)){
            throw new SqrlException(
                'No command was included in the request', 
                SqrlException::INVALID_REQUEST
            );
        }
        if(in_array($this->cmd, array('setkey','setlock','enable','delete')) &&
                empty($this->verifyUnlockKey)){
            throw new SqrlException(
                'Command requires a verify unlock key. None was included in the request', 
                SqrlException::INVALID_REQUEST
            );
        }
    }
    
    protected function decodeServerData($serverData,$get,$server)
    {
        if (substr($serverData,0,7)==='sqrl://' || substr($serverData,0,6)==='qrl://'){
            $this->decodeServerUrl($serverData, $get['nut'], !empty($server['HTTPS']));
        } else {
            $this->decodeServerResponse($serverData,!empty($server['HTTPS']));
        }
    }
    
    protected function decodeServerUrl ($url,$nut,$https)
    {
        $this->requestType = self::INITIAL_REQUEST;
        $this->validator->setNonce($nut);
        if (!$this->validator->matchServerData(self::INITIAL_REQUEST,$https,$url)) {
            throw new SqrlException(
                    'Requested URL doesn\'t match expected URL', 
                    SqrlException::SIGNED_URL_DOESNT_MATCH
                    );
        }
    }
    
    protected function decodeServerResponse($data,$https)
    {
        $serverVer = 0;
        $serverQry = '';
        $serverLnk = '';
        $serverSfn = '';
        $serverAsk = '';
        $inputAsArray = explode("\n",$data);
        foreach ($inputAsArray as $individualInputs) {
            list($key,$val)=explode("=",$individualInputs);
            $val = trim($val);//strip off the \r
            switch ($key) {
                case 'ver':
                    $serverVer = $val;
                    break;
                case 'nut':
                    $this->validator->setNonce($val);
                    break;
                case 'tif':
                    $this->requestType = (int)$val;
                    break;
                case 'qry':
                    $serverQry = $val;
                    break;
                case 'lnk':
                    $serverLnk = $val;
                    break;
                case 'sfn':
                    $serverSfn = $val;
                    break;
                case 'ask':
                    $serverAsk = $val;
                    break;
            }
        }
        if (!$this->validator->matchServerData($this->requestType,$https,array(
            'ver'=>$serverVer,
            'qry'=>$serverQry,
            'lnk'=>$serverLnk,
            'sfn'=>$serverSfn,
            'ask'=>$serverAsk
            )
        )) {
            throw new SqrlException('Request doesn\'t match expected request', SqrlException::SIGNED_URL_DOESNT_MATCH);
        }
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
     * @throws \Exception
     * @throws SqrlException
     * @return string
     */
    public function getResponseMessage()
    {
        //handle initial request parsing errors
        if (!empty($this->message)) {
            return $this->message;
        }
        try {
            $this->verifyRequest();
            $actions = explode('~', $this->cmd);
            $acceptedActions = array('setKey','setLock','disable','enable','delete','create','login','logme','logoff');
            $responseCode = self::IP_MATCH;//just set this for now, need to set up no enforce IP handling
            if ($this->requestType === self::INITIAL_REQUEST) {
                $continue=true;
            } else {
                $continue=false;
            }
            foreach ($actions as $act) {
                if (!in_array($act, $acceptedActions)) {
                    return $this->formatResponse(
                        'Command not found', 
                        self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE|self::IP_MATCH,
                        false
                    );
                }
                $actionResponse = $this->$act($continue);
                if ($actionResponse&self::COMMAND_FAILED) {
                    return $this->formatResponse(
                        $act.' command failed', 
                        $actionResponse,
                        false
                    );
                }
                $responseCode |= $actionResponse;
            }
            return $this->formatResponse('Commands successful',$responseCode,$continue);
        } catch (SqrlException $ex) {
            switch ($ex->getCode()) {
                case SqrlException::ENFORCE_IP_FAIL:
                    return $this->formatResponse(
                        'IPs do not match', 
                        self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE
                    );
                case SqrlException::SIGNATURE_NOT_VALID:
                    return $this->formatResponse(
                        'Signature did not match', 
                        self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE|self::IP_MATCH,
                        false
                    );
            }
        }
    }
    
    /**
     * Performs the log in action
     * 
     * @return int
     */
    protected function login($continue)
    {
        $userKey = empty($this->oldKey)?$this->authenticateKey:$this->oldKey;
        $response = 0;
        if (!is_null($this->store)) {
            //find the user's key to see if there already is a record
            $userData = $this->store->retrieveAuthenticationRecord(base64_encode($userKey));
            if (!empty($userData)) {
                if ($userData['disabled']==1 && !$continue) {
                    //if the user is trying to finish logging in with a disabled account, reject it
                    return self::COMMAND_FAILED|self::SQRL_SERVER_FAILURE|self::IP_MATCH;
                }
                $response |= empty($this->oldKey)?self::ID_MATCH:self::PREVIOUS_ID_MATCH;
                $response |= $userData['disabled']==0?self::SQRL_ENABLED:0;
                $response |= $continue?0:self::USER_LOGGED_IN;
                return $response;
            } else {
                //TODO: this should handle allowing a user to create an anonymous account if allowed
                return 0;
            }
        } else {
            // TODO: How should this be handled modularly?
            // Should we allow the calling code to set whether or not the key was matched
            // or should we have a different set of commands to allow the calling
            // code to interact with the commands more directly?
        }
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
        echo $this->getResponseMessage();
    }

    protected function verifyRequest()
    {
        $this->validator->validate();
        if (!empty($this->oldKey)) {
            $this->validator->validateSignature($this->oldKey, $this->oldKeySig);
        }
        if (!empty($this->unlockRequestKey)) {
            $this->validator->validateSignature($this->unlockRequestKey, $this->unlockRequestSig);
        }
    }

    /**
     * Formats a response to send back to a client
     * 
     * @param string $display A human readable message
     * @param int $code The TIF code to send back to the user
     * @param boolean $continue Whether to send a new nut expecting a response back
     * 
     * @return string
     */
    protected function formatResponse($display, $code,$continue=true)
    {
        $resp = 'ver='.$this->acceptedVersions."\r\n"
            .'tif='.$code."\r\n"
            .'sfn='.$this->sfn;
        if ($continue) {//if the command failed, the user can't send a second response
            $resp.="\r\nnut=".$this->getNonce($code,$this->authenticateKey);
        }
        if (!empty($this->lnk)) {
            $resp.= "\r\nlnk=".$this->lnk;
        }
        if (!empty($this->qry)) {
            $resp.= "\r\nqry=".$this->qry;
        }
        if (!empty($this->ask)) {
            $resp.= "\r\nask=".$this->ask;
        }
        return $resp;
    }
    
    protected function getNonce($action,$key)
    {
        if(!is_null($this->sqrlGenerator)) {
            return $this->sqrlGenerator->getNonce($action, $key);
        }
        //todo allow direct nonce setting?
    }
    
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
