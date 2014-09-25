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
    use Trianglman\Sqrl\SqrlStoreInterface;
    require_once(__DIR__.'/../vendor/autoload.php');
    session_start();
    
    $config = new \Trianglman\Sqrl\SqrlConfiguration();
    $config->load(__DIR__.'/../config/sqrlconfig.json');
    $store = new \Trianglman\Sqrl\SqrlStore($config);
    
    if (isset($_SESSION['publicKey'])) {
        $acccount = $store['SqrlStorage']->retrieveAuthenticationRecord(
                $_SESSION['publicKey'], 
                array(SqrlStoreInterface::SUK,  SqrlStoreInterface::VUK)
                );
    }
    if (empty($account)) {
        header('Location: /index.php',true,303);//send the user back to the index page to get a new nonce
    }
?>

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>SQRL Account</title>
    </head>
    <body>
        <h1>You have successfully signed in using SQRL</h1>
        
        <ul>
            <!--These values should be base64 encoded in the database/session, but better not to trust data I didn't make here-->
            <li>Public key: <?php echo htmlentities(base64_encode($_SESSION['publicKey']), ENT_HTML5, 'UTF-8');?></li>
            <li>SUK: <?php echo htmlentities($acccount['suk'], ENT_HTML5, 'UTF-8');?></li>
            <li>VUK: <?php echo htmlentities($acccount['vuk'], ENT_HTML5, 'UTF-8');?></li>
        </ul>
        <p>
            <a href="/login/logout.php">Logout</a>
        </p>
    </body>
</html>
