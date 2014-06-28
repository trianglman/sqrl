<?php
namespace Trianglman\Sqrl\Ed25519;
require_once(__DIR__.'/../src/Trianglman/Sqrl/Ed25519/CryptoInterface.php');
require_once(__DIR__.'/../src/Trianglman/Sqrl/Ed25519/Crypto.php');

$sk = $argv[1];
$messageSrc = $argv[2];
if(!file_exists($messageSrc)){
    $m = $messageSrc;
}
else{
    $m = file_get_contents($messageSrc);
}

$obj = new Crypto();
$pk = $obj->publickey($sk);

$sig = $obj->signature($m, $sk, $pk);

echo 'Message: "'.$m."\"\n";
echo 'Public Key(base64url): '.base64UrlEncode($pk)."\n";
echo 'Signature(base64Url) : '.base64UrlEncode($sig)."\n";
echo 'Verifies? '.($obj->checkvalid($sig, $m, $pk)?'yes':'no')."\n";



function base64UrlEncode($string)
{
  $base64 = base64_encode($string);
  $urlencode = str_replace(array('+','/'), array('-','_'), $base64);
  $urlencode = trim($urlencode, '=');
  return $urlencode;
}
