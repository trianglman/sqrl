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

namespace trianglman\sqrl\interfaces;

/**
 * A handler to process the authentication of SQRL clients
 * 
 * This class will process a request, send it to the validator, then depending on
 * the type of request, send a success message, send an error message, or send a
 * request for more information (e.g. initiate the second loop to create a new user)
 *
 * @author johnj
 */
interface SqrlRequestHandler {
    
    /**
     * The SQRL Server version
     * @const
     * @var int
     */
    const VERSION=1;
    
    /**
     * A basic SQRL authentication request, no special parameters
     * @const
     * @var int
     */
    const AUTHENTICATION_REQUEST=1;
    /**
     * A second loop response from a user who's public key was not recognized
     * @const
     * @var int
     */
    const NEW_ACCOUNT_REQUEST=2;
    /**
     * A request from the user to disable their stored authentication key
     * @const
     * @var int
     */
    const DISABLE_REQUEST=3;
    /**
     * A request from the user to replace their current authentication information
     * @const
     * @var int
     */
    const REKEY_REQUEST=4;
    /**
     * A second loop response from a user to re-enable a disabled key
     * @const
     * @var int
     */
    const REENABLE_REQUEST=5;
    /**
     * A second loop response from a user to replace their current stored 
     * authentication key
     * @const
     * @var int
     */
    const MIGRATE_REQUEST=6;
    /**
     * A second loop response from a user to replace all current authentication
     * information
     * @const
     * @var int
     */
    const REPLACE_REQUEST=7;
    /**
     * A second loop response from a user to replace their Identity Lock information
     * @const
     * @var int
     */
    const RELOCK_REQUEST=8;
    /**
     * A second loop response for all Identity Lock related requests
     * 
     * This should be set and stored with the nonce and will be overriden during 
     * request processing
     * 
     * @const
     * @var int
     */
    const REKEY_REQUEST_LOOP2=9;
    
    //ERROR CODES
    
    /**
     * Request was completed successfully
     * 
     * @const
     * @var int
     */
    const OK=1;
    /**
     * The request was not properly formatted or was missing information
     * 
     * @const
     * @var int
     */
    const INVALID_REQUEST=2;
    /**
     * The IP of the request did not match the nonce IP
     * 
     * @const
     * @var int
     */
    const ENFORCE_IP_FAILED=3;
    /**
     * The serverurl value did not match what was supplied by the server
     * 
     * @const
     * @var int
     */
    const SERVERURL_MISMATCH=4;
    /**
     * The signature did not match the key
     * 
     * @const
     * @var int
     */
    const INVALID_SIGNATURE=5;
    /**
     * A second loop is required to supply more information
     * 
     * @const
     * @var int
     */
    const MORE_INFORMATION=6;
    
    /**
     * Initializes the Request Handler
     * 
     * @param \trianglman\sqrl\interfaces\SqrlValidate $val Sets the validator that will check the response
     * @param \trianglman\sqrl\interfaces\SqrlStore $store [Optional] Sets storage for submitted authorization keys
     * @param \trianglman\sqrl\interfaces\SqrlGenerate $gen [Optional] Sets the nonce generator for loop two
     * 
     * @return void
     */
    public function __construct(SqrlValidate $val,SqrlStore $store=null,SqrlGenerate $gen=null);
    
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
    public function parseRequest($get,$post,$server);
    
    /**
     * Gets the type of request the user made
     * 
     * The return value will be one of the predefined constants
     * 
     * @return int
     */
    public function getRequestType();
    
    /**
     * Gets the text message to be returned to the SQRL client
     * 
     * @return string
     */
    public function getResponseMessage();
    
    /**
     * Gets the numeric HTTP code to return to the SQRL client
     * 
     * Currently the spec only uses the 200 code and any error message is in the
     * test message response
     * 
     * @return int
     */
    public function getResponseCode();
    
    /**
     * A helper function to send the response message and code to the SQRL client
     * 
     * @return void
     */
    public function sendResponse();
}
