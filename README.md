sqrl
====

PHP Server side implementation of a SQRL generator/listener


Software Requirements
====

* Composer - http://getcomposer.org
  * Endroid/qrcode Loaded automatically by Composer - https://github.com/endroid/QrCode
* libsodium - https://github.com/jedisct1/libsodium
* PHP-Sodium - https://github.com/alethia7/php-sodium

Purpose
====

The goal of this software is to provide a simple PHP implementation of Steve
Gibson's SQRL authentication proposal. This library will allow any site using it
to generate the QR code with a nonce, validate a signed nonce, and store the 
public key for connection to a site account. 

Installation
====

###Composer

```json
"repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/trianglman/sqrl"
        }
    ],
    "require": {
        "trianglman/sqrl": "dev-master"
    }
```

Configuration
====

If you want to have the library automatically store generated nonces and validated
public keys, first generate the database tables based on the supplied 
trianglman/sqrl/sample.sql, then create a JSON config file based on the sample
provided in trianglman/sqrl/config.sample.json. You can then configure the 
generator or validator by calling the appropriate `loadConfigFromJSON($filepath);`
method.

If you would rather manage storage of this information in your own tables, the 
only configuration necessary is to set the SQRL path for the nonce generator:

```php
$generator = new \trianglman\sqrl\SqrlGenerate();
$generator->setPath('sqrl://example.com/sqrl');
//...
```

You can also configure the size of the QR code generated and the amount of 
padding between the image edge and the start of the code, as well as supply
your own salt for the nonce:

```php
//...

$generator->setHeight(300);
$generator->setPadding(10);
$generator->setSalt('foo');

//...
```

Usage
====

**Generate a nonce**
```php
//Initialize the generator
$generator = new \trianglman\sqrl\SqrlGenerate();
$generator->loadConfigFromJSON('/path/to/config');

//output the QR file to stdout
$generator->render();

//get the nonce for other uses, i.e. link, etc.
$nonce = $generator->getNonce();
```

**Verify a user's input**
```php
//initialize the validator
$validator = new \trianglman\sqrl\SqrlValidate();
$validator->loadConfigFromJSON('/path/to/config');

//supply the user input
$validator->setPublicKey($inputPublicKey);
$validator->setNonce($inputNonce);
$validator->setCryptoSignature($inputSignedNonce);

//check validation
if($validator->validate()){
  //do something...
  
  //get an identifier for the public key 
  //you can then connect this to a user database.
  //If a public key matching this user's already exists, that ID is returned
  $keyId = $validator->storePublicKey();
}
```