<?php
$opts = 'v:';//version defaults to 1
$opts.= 's:';//server sent data, can be a file or a string
$opts.= 'c:';//command
$opts.= 'a:';//ask response defaults to none
$opts.= 'i:';//IDK
$opts.= 'p:';//pIDK defaults to none
$opts.= 'u:';//SUK defaults to none
$opts.= 'v:';//VUK defaults to none

$suppliedOpts = getopt($opts);
$version = isset($suppliedOpts['v'])?$suppliedOpts['v']:1;
if(!file_exists('file://'.$suppliedOpts['s'])){
    $serverData = $suppliedOpts['s'];
}
else{
    $serverData = file_get_contents($suppliedOpts['s']);
}

$command = $suppliedOpts['c'];
$idk = $suppliedOpts['i'];
if(isset($suppliedOpts['p'])){
    $pidk = $suppliedOpts['p'];
}
if(isset($suppliedOpts['u'])){
    $suk = $suppliedOpts['u'];
}
if(isset($suppliedOpts['v'])){
    $vuk = $suppliedOpts['v'];
}
if(isset($suppliedOpts['a'])){
    $ask = $suppliedOpts['a'];
}

$outfile = $argv[$argc-1];
$fp = fopen($outfile,'w');
$data = "server=".  base64UrlEncode($serverData).'&';
$data.= 'client='.base64UrlEncode(
    "ver=$version\r\n".
    "idk=$idk\r\n".
    "cmd=$command".
    (isset($pidk)?"\r\npidk=$pidk":'').
    (isset($suk)?"\r\nsuk=$suk":'').
    (isset($vuk)?"\r\nvuk=$vuk":'').
    (isset($ask)?"\r\nval=$ask":'')
    );

fwrite($fp,$data);
fclose($fp);

function base64UrlEncode($string)
{
    $base64 = base64_encode($string);
    $urlencode = str_replace(array('+','/'), array('-','_'), $base64);
    return trim($urlencode, '=');
}