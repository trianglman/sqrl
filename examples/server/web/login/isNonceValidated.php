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
    $db = new \PDO($config->getDsn(),$config->getUsername(),$config->getPassword());
    $store = new \Trianglman\Sqrl\SqrlStore($config);
    $store->setDatabaseConnection($db);
        
    $validated = false;
    if (isset($_SESSION['nonce'])) {
        $validated =  (int)$store->retrieveNutRecord(
                $_SESSION['nonce'],
                array(\Trianglman\Sqrl\SqrlStoreInterface::VERIFIED)
                ) > 0;
        if ($validated) {
            $SQL = "SELECT related_public_key FROM sqrl_nonce n JOIN sqrl_nonce_relationship r ON r.new_nonce = n.nonce WHERE r.old_nonce = ?";
            $stmt = $db->prepare($SQL);
            $stmt->execute(array($_SESSION['nonce']));
            $result = $stmt->fetchColumn(0);
            $_SESSION['publicKey'] = $result[0];
            unset($_SESSION['nonce']);
            unset($_SESSION['generatedTime']);
            header('Location: /account.php',true,303);
        }
    } else {
        header('Location: /index.php',true,303);//send the user back to the index page to get a new nonce
    }
    
    
?>

<html>
  <head>
    <title>Verifying Login...</title>
    <?php if (isset($_SESSION['nonce'])): ?>
    <META http-equiv="refresh" content="5;URL=/login/isNonceValidated.php">
    <?php endif;?>
  </head>
  <body>
      <p>
          <?php if (isset($_SESSION['nonce'])): ?>
          Your log in has not been validated. This page will refresh in 5 seconds. <a href="/login/isNonceValidated.php">Click here to check again.</a>
          <?php endif;?>
      </p>
  </body>
</html>