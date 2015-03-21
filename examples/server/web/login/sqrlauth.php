<?php

/*
 * The MIT License
 *
 * Copyright 2014 johnj.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
    namespace sqrlexample;

    require_once(__DIR__.'/../../vendor/autoload.php');
    require_once(__DIR__.'/../../includes/ExampleStatefulStorage.php');

    $config = new \Trianglman\Sqrl\SqrlConfiguration();
    $config->load(__DIR__.'/../../config/sqrlconfig.json');
    $conn = new \PDO('mysql:host=localhost;dbname=sqrl', 'example', 'bar');
    $store = new ExampleStatefulStorage($conn,$_SERVER['REMOTE_ADDR']);
    $generator = new \Trianglman\Sqrl\SqrlGenerate($config,$store);
    if(extension_loaded("ellipticCurveSignature")) {
        $sigValidator = new \Trianglman\Sqrl\EcEd25519NonceValidator();
    } else {
        $sigValidator = new \Trianglman\Sqrl\Ed25519NonceValidator();
    }
    $validator = new \Trianglman\Sqrl\SqrlValidate($config,$sigValidator,$store);
    $handler = new \Trianglman\Sqrl\SqrlRequestHandler($config,$validator,$store,$generator);
    if (!empty($_POST)) {//this is only necessary for early clients that were not setting the Content-Type header properly
        $post = $_POST;
    } else {
        $post = array();
        parse_str(file_get_contents('php://input'), $post);
    }
    $handler->parseRequest($_GET, $post,$_SERVER);
    $resp = $handler->getResponseMessage();
    echo $resp;
    
    //This is extra logging code that is only being used while testing clients
    //Production servers should not do this
    $request = json_encode(array('get'=>$_GET,'post'=>$hardPost,'ip'=>$_SERVER['REMOTE_ADDR'],'uri'=>$_SERVER['REQUEST_URI']));
    $decodedClient = $handler->base64URLDecode($hardPost['client']);
    $reqHeaders = json_encode(apache_request_headers());
    $response = $handler->base64URLDecode($resp)."\r\nerror=".$handler->error;
    $sql = 'INSERT INTO nutTransactions (nut,request, clientData, responseData,reqHeaders) VALUES (:n,:req,:cli,:resp,:hdr)';
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':n', $_GET['nut']);
    $stmt->bindParam(':req', $request);
    $stmt->bindParam(':cli', $decodedClient);
    $stmt->bindParam(':resp', $response);
    $stmt->bindParam(':hdr', $reqHeaders);
    $stmt->execute();