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

    $config = new \Trianglman\Sqrl\SqrlConfiguration();
    $config->load(__DIR__.'/../../config/sqrlconfig.json');
    $store = new \Trianglman\Sqrl\SqrlStore($config);
    //the generator is used on this page to handle creating/storing the second loop nonce, where necessary
    $generator = new \Trianglman\Sqrl\SqrlGenerate($config,$store);
    //I strongly recommend using an extension for ED25519 validation. The PHP version is incredibly slow.
    if(extension_loaded("libsodium")) {
        $sigValidator = new \Trianglman\Sqrl\SodiumNonceValidator();
    } elseif(extension_loaded("ellipticCurveSignature")) {
        $sigValidator = new \Trianglman\Sqrl\EcEd25519NonceValidator();
    } else {
        $sigValidator = new \Trianglman\Sqrl\Ed25519NonceValidator();
    }
    $validator = new \Trianglman\Sqrl\SqrlValidate($config,$sigValidator,$store);
    $handler = new \Trianglman\Sqrl\SqrlRequestHandler($config,$validator,$store,$generator);
    
    $handler->parseRequest($_GET, $_POST,$_SERVER);
    echo $handler->getResponseMessage();