#include <iostream>
#include <map>

extern "C" {
#include "jansson.h"
}

using namespace std;

namespace jwtcpp{

	/**
	 * A class representing a JSON Web Token.
	 *
	 * JWT are defined in http://self-issued.info/docs/draft-jones-json-web-token.html
	 * This class
	 *
	 **/
	class JWT{
		private:
			string algorithm;
			json_t* payload;
			string signature;
			string signed_data;

		public:
			/**
			 * JWT class constructor.
			 *
			 * @param string the name of the algorithm to be used to sign or
			 *               verify the signature of the token.
			 * @param map<string, string> the payload contained in the token
			 * @param string the signature
			 * @param string the signed data
			 **/
			JWT(string algorithm, json_t* payload, string signature, string signed_data);

			/**
			 * Check the current token against the given public key.
			 *
			 * @param string the public key data.
			 *
			 * @return bool True if the signature is correct, false otherwise.
			 **/
			bool checkSignature(string keyData);
	};

    /**
     * Parse a string into a JSON Web Token.
     *
	 * @param string the text to parse (the encoded and signed JWT)
	 *
	 * @return *JWT a JWT object.
	 **/
	JWT* parse(string jwt);

	/**
	 * Generates and sign a JWT from a map of <string, string> (dict).
	 *
	 * @param string the name of the algorithm used to sign the token.
	 * @param string the key that will be used to sign the token.
	 * @param map<string, string> a map containing the payload.
	 *
	 * @return string the encoded and signed JSON Web Token.
	 **/
	string generate(string algorithm, string key, map<string, string>* payloadMap);
}
