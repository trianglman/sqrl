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
    require_once(__DIR__.'/../vendor/autoload.php');
    require_once(__DIR__.'/../includes/ExampleStatefulStorage.php');
    session_start();
    
    //configuration stuff
    $config = new \Trianglman\Sqrl\SqrlConfiguration();
    $config->load(__DIR__.'/../config/sqrlconfig.json');
    $store = new ExampleStatefulStorage(new \PDO('mysql:host=localhost;dbname=sqrl', 'example', 'bar'),$_SERVER['REMOTE_ADDR'],$_SESSION);
    $generator = new \Trianglman\Sqrl\SqrlGenerate($config,$store);
    
    $nonce = $generator->getNonce();
    $sqrlUrl = $generator->getUrl();
?>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>SQRL Example Server</title>
    </head>
    <body>
        <h1>Welcome to the SQRL PHP Example Server</h1>
        
        <p>
            This server should enable you to walk through a number of test scenarios using the SQRL protocol.
        </p>
        <p>
            Please use the below link/QR code to sign in and either create a new account or view your already entered account information.
        </p>
        <p style="text-align: center;">
            <a href="<?php echo $sqrlUrl;?>">
            <img src="sqrlImg.php?nonce=<?php echo $nonce;?>" title="Click or scan to log in" alt="SQRL QR Code" />
            </a><br />
            <a href="<?php echo $sqrlUrl;?>"><?php echo $sqrlUrl;?></a><br />
            <a href="/login/isNonceValidated.php">Verify Login</a><!-- This should also be automated with JavaScript for a smoother UX-->
        </p>
    </body>
</html>
