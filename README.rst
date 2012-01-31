JSON Web Tokens C++ lib
#######################

.. warning::

    This library is a work in progress. It's not ready for production yet.

This lib exposes a simple class to work with signed JSON Web Tokens (JWT).
It had been developped by Mozilla while making a C++ implementation of
BrowserID.

JSON Web Tokens (JWT) are described `in this document
<http://self-issued.info/docs/draft-jones-json-web-token.html>`_

Installation
============

Running `make` and `make install` should do the trick.

Dependencies
============

You need to have the following library installed on your system:

* cryptopp for the crypto related stuff
* jansson to deal with json

How to use it?
==============

Once installed, jwtcpp provides a bunch of functions and methods so you can
extract information about the JSON Web Tokens. 

Here is an example application showing how you can use the library:

.. code-block:: cpp

    # include "jwtcpp.h"
    
    using namespace std;

    // It is possible to create a JWT from a string and to interact with it

    JWT* jwt = JWT::fromString();
    cout << jwt->algorithm << endl;
    cout << jwt->signature << endl;
    cout << jwt->signed_data << endl;

    json_t* payload = jwt->payload;

    // It is also possible to create a JWT programatically and then serialize
    // it as a string
    string serialized = jwt->generate(key);

    // There is also a static method available if you want to directly
    // serialize a mapping
    Jwt* jwt = JWT::generate(mapping, key);

`jwtcpp` also provides a cli application able to generate and decode JWT. You can
invoke it like this:

.. code-block:: bash

    $ jwtcpp --generate --key=path/to/key.crt --data="{'json data': true}"
    XXX the output here

    $ jwtcpp --extract | cat token.jwt
    XXX output

    $ jwtcpp --extract --data "yourcontenthere"
    XXX output
