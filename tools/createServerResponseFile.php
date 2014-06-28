<?php
$opts = 'v:';//version defaults to 1
$opts.= 'n:';//nut
$opts.= 't:';//tif value (can be hex or decimal)
$opts.= 'q:';//query defaults to none
$opts.= 'l:';//link defaults to none
$opts.= 's:';//server friendly name
$opts.= 'a:';//ask defaults to none

$suppliedOpts = getopt($opts);
$version = isset($suppliedOpts['v'])?$suppliedOpts['v']:1;
$nut = $suppliedOpts['n'];
$tif = $suppliedOpts['t'];
if(substr($tif,0,2)==='0x'){
    $tif= hexdec($tif);
}
if(isset($suppliedOpts['q'])){
    $query = $suppliedOpts['q'];
}
if(isset($suppliedOpts['l'])){
    $link = $suppliedOpts['l'];
}
$friendlyName = $suppliedOpts['s'];
if(isset($suppliedOpts['a'])){
    $ask = $suppliedOpts['a'];
}

$outfile = $argv[$argc-1];
$fp = fopen($outfile,'w');
$data = "ver=$version\r\ntif=$tif\r\nsfn=$friendlyName\r\nnut=$nut\r\n";
if(isset($query)){
    $data.= "qry=$query\r\n";
}
if(isset($link)){
    $data.= "lnk=$link\r\n";
}
if(isset($ask)){
    $data.= "ask=$ask";
}

fwrite($fp,$data);
fclose($fp);

