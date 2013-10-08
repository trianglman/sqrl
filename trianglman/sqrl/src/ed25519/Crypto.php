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

namespace trianglman\sqrl\src\ed25519;

ini_set('xdebug.max_nesting_level', 0);
/**
 * A PHP implementation of the Python ED25519 library
 *
 * @author johnj
 * 
 * @link http://ed25519.cr.yp.to/software.html Other ED25519 implementations this is referenced from
 */
class Crypto implements \trianglman\sqrl\interfaces\ed25519\Crypto{
    protected $b;
    protected $q;
    protected $l;
    protected $d;
    protected $I;
    protected $By;
    protected $Bx;
    protected $B;
    
    public function __construct() {
        $this->b = 255;
        $this->q = "57896044618658097711785492504343953926634992332820282019728792003956564819949";//bcsub(bcpow(2, 255),19);
        $this->l = "7237005577332262213973186563042994240829374041602535252466099000494570602496";//bcadd(bcpow(2,252),27742317777372353535851937790883648493);
        $this->d = "-2412002500205643740163293893873104449252336231509255826590736182645207578106868355";//bcmul(-121665,$this->inv(121666));
        $this->I = "25418358934029606749985806358096902613962102590680832505260377150198452456287";//$this->expmod(2,  bcdiv((bcsub($this->q,1)),4),$this->q);
        $this->By = "76293945312500";//bcmul(4,$this->inv(5));
        $this->Bx = "91223544677139905557058234613620631313076257731888553244725450088484129695438";//$this->xrecover($this->By);
        $this->B = array("33327500058481807845272742109276677386441265399068271224996658084527564875489", "76293945312500");//array(bcmod($this->Bx,$this->q),bcmod($this->By,$this->q));
    }
    
    protected function H($m)
    {
        return hash('sha512', $m);
    }
    
    protected function expmod($b,$e,$m)
    {
        if($e==0){return 1;}
        $t = bcmod(bcpow($this->expmod($b,bcdiv($e,2,0),$m),2),$m);
        if($e&1){$t = bcmod(bcmul($t,$b),$m);}
        return $t;
    }
    
    protected function inv($x)
    {
        return $this->expmod($x, bcsub($this->q,2), $this->q);
    }
    
    protected function xrecover($y)
    {
        $xx = bcmul(bcsub(bcpow($y,2),1),$this->inv( bcadd(bcmul($this->d,bcpow($y,2)),1)));
        $x = $this->expmod($xx,bcdiv(bcadd($this->q,3),8,0),$this->q);
        if( bcmod(bcsub(bcpow($x,2),$xx),$this->q) != 0){$x=bcsub($this->q,$x);}
        if(bcmod($x,2) !=0){$x=bcsub($this->q,$x);}
        return $x;
    }
    
    protected function edwards($P,$Q)
    {
        list($x1,$y1) = $P;
        list($x2,$y2) = $Q;
        $x3 = bcmul(bcadd(bcmul($x1,$y2),bcmul($x2,$y1)),$this->inv(bcadd(1,bcmul($this->d,bcmul($x1,bcmul($x2,bcmul($y1,$y2)))))));
        $y3 = bcmul(bcadd(bcmul($y1,$y2),bcmul($x1,$x2)),$this->inv(bcsub(1,bcmul($this->d,bcmul($x1,bcmul($x2,bcmul($y1,$y2)))))));
        return array(bcmod($x3,$this->q), bcmod($y3,$this->q));
    }
    
    protected function scalarmult($P,$e)
    {
        if($e == 0){return array(0,1);}
        $Q = $this->scalarmult($P, bcdiv($e,2,0));
        return ((bcmod($e,2)==1)?$this->edwards($Q, $P):$this->edwards($Q, $Q));
    }
    
    protected function bitsToString($bits)
    {
        $string = '';
        for($bytePos = 0;$bytePos<strlen($bits)/16;$bytePos++){
            $binchar = substr($bits, $bytePos*16, 16);
            $string.=bin2hex($binchar);
        }
        return $string;
    }
    
    protected function dec2bin_i($decimal_i)
    {

        $binary_i = '';
        do{
            $binary_i = bcmod($decimal_i,'2') . $binary_i;
            $decimal_i = bcdiv($decimal_i,'2',0);
         } while (bccomp($decimal_i,'0'));

        return($binary_i);
    }    
    protected function encodeint($y)
    {
        $bits = str_pad($this->dec2bin_i($y), $this->b, '0', STR_PAD_LEFT);
        return $this->bitsToString($bits);
    }
    
    protected function encodepoint($P)
    {
        list($x,$y) = $P;
        $bits = str_pad($this->dec2bin_i(substr($y, 0,$this->b-1)), $this->b-1, '0', STR_PAD_LEFT);
        $bits.=(bcmod($x,2)==1?'1':'0');
        return $this->bitsToString($bits);
    }
    
    protected function bit($h,$i)
    {
        return (ord($h[(int)bcdiv($i,8,0)]) >> bcmod($i,8) ) &1;
    }
    
    /**
     * Generates the public key of a given private key
     * 
     * @param string $sk the secret key
     * @return string
     */
    public function publickey($sk)
    {
        $h = $this->H($sk);
        $sum = 0;
        for($i=3;$i<$this->b-2;$i++){
            $sum=bcadd($sum,bcmul(bcpow(2,$i),$this->bit($h,$i)));
        }
        $a = bcadd(bcpow(3,$this->b-2),$sum);
        $A = $this->scalarmult($this->B, $a);
        return $this->encodePoint($A);
    }
    
    protected function Hint($m)
    {
        $h = $this->H($m);
        $sum = 0;
        for($i=0;$i<$this->b*2;$i++){
            $sum+=pow(2,$i)*$this->bit($h,$i);
        }
        return $sum;
    }
    
    public function signature($m,$sk,$pk)
    {
        $h = $this->H($sk);
        $a = pow(2,($this->b-2));
        for($i=3;$i<$this->b-2;$i++){
            $a+=pow(2,$i)*$this->bit($h, $i);
        }
        $r = $this->Hint(substr($h, $this->b/8, ($this->b/4-$this->b/8))).$m;
        $R = $this->scalarmult($this->B, $r);
        $S = ($r.$this->Hint($this->encodepoint($R).$pk.$m) *$a)%$this->l;
        return $this->encodepoint($R).$this->encodeint($S);
    }
    
    protected function isoncurve($P)
    {
        list($x,$y) = $P;
        return((-$x*$x) + ($y*y) - 1 - $this->d*$x*$x*$y*$y) % $this->q == 0;
    }
    
    protected function decodeint($s)
    {
        $sum = 0;
        for($i=0;$i<$this->b;$i++){
            $sum+=pow(2,$i)*$this->bit($s,$i);
        }
        return $sum;
    }
    
    protected function decodepoint($s)
    {
        $y = 0;
        for($i=0;$i<$this->b-1;$i++){
            $y+=pow(2,$i)*$this->bit($s,$i);
        }
        $x = $this->xrecover($y);
        if($x&1 !=$this->bit($s,$this->b-1)){
            $x = $this->q-$x;
        }
        $P = array($x,$y);
        if(!$this->isoncurve($P)){
            throw new \Exception("Decoding point that is not on curve");
        }
        return $P;
    }
    
    public function checkvalid($s,$m,$pk)
    {
        if(strlen($s)!=$this->b/4){ throw new \Exception('Signature length is wrong');}
        if(strlen($pk)!=$this->b/4){throw new \Exception('Public key length is wrong');}
        $R = $this->decodepoint(substring($s,0,$this->b/8));
        $A = $this->decodepoint($pk);
        $S = $this->decodeint(substr($s, $this->b/8, $this->b/4));
        $h = $this->Hint($this->encodepoint($R).$pk.$m);
        return $this->scalarmult($this->B, $S) == $this->edwards($R, $this->scalarmult($A, $h));
    }
}
