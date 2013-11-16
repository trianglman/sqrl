sqrl
====

PHP Server side implementation of a SQRL generator/listener

This project is in pre-alpha until there is a defined reference implementation.

Follow the conversation at https://www.grc.com/groups/sqrl for updates on the 
standard.


Software Requirements
====

* Composer - http://getcomposer.org
  * Endroid/qrcode Loaded automatically by Composer - https://github.com/endroid/QrCode

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

If you would rather manage storage of this information in your own tables, you can
configure the generator manually:

```php
$generator = new \trianglman\sqrl\src\SqrlGenerate();
//whether SQRL responses should come back over SSL (sqrl://)
$generator->setSecure(true);
//the domain sqrl clients should generate their key off of
$generator->setKeyDomain('www.example.com');
//the path to the SQRL authentication script relative to the key domain
$generator->setAuthenticationPath('sqrl/login.php');

//The above would generate a SQRL URL pointing to 
//sqrl://www.example.com/sqrl/login.php
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
$generator = new \trianglman\sqrl\src\SqrlGenerate();
$generator->loadConfigFromJSON('/path/to/config');

//output the QR file to stdout
$generator->render();

//get the nonce for other uses, i.e. link, etc.
$nonce = $generator->getNonce();
```

**Verify a user's input**
```php
//initialize the validator
$validator = new \trianglman\sqrl\src\SqrlValidate();
$validator->loadConfigFromJSON('/path/to/config');
$validator->setValidator(new \trianglman\sqrl\src\ed25519\Crypto());

//initialize the request handler
$requestResponse = new \trianglman\sqrl\src\SqrlRequestHandler($validator);
$requestResponse->parseRequest($_GET, $_POST, $_SERVER);

//check validation
$requestResponse = $obj->getResponseMessage();
$requestResponseCode = $obj->getResponseCode();

//OR

//Let the request handler also handle the response
$reqHandler->sendResponse();
```