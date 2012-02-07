#include <iostream>
#include "string.h"

#include "utils.h"
#include "jwt.h"
#include "keys.h"

#include "cryptopp/dsa.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"

#include "unittest++/UnitTest++.h"

extern "C" {
#include "jansson.h"
}

using namespace std;
using namespace jwtcpp;
using namespace CryptoPP;

/**
 * This file contains tests for the JWT generation and parsing.
 **/

TEST(DecodeBase64)
{
	// extra == should be added on the fly
    string decoded = decodeBase64("eyJ0ZXN0IjogInllYWgifQ");
	CHECK_EQUAL("{\"test\": \"yeah\"}", decoded);
}

TEST(EncodeBase64)
{
	// when encoding, the extra "=" should be removed
    string base64json = encodeBase64("{\"test\": \"yeah\"}");
	CHECK_EQUAL("eyJ0ZXN0IjogInllYWgifQ", base64json);
}

TEST(DecodeJSONBytes)
{
	// An encoded b64 encoded JSON value should decode successfully
    json_t* root = decodeJSONBytes("eyJ0ZXN0IjogInllYWgifQ");
	// check that the returned object is a json object. It should contain the
	// "test" chain.
    CHECK_EQUAL("yeah", json_string_value(json_object_get(root, "test")));
}

TEST(EncodeJSONBytes)
{
	json_error_t* errors;
	json_t* json = json_loads("{\"key\":\"value\"}", 0, errors);
	CHECK_EQUAL("eyJrZXkiOiAidmFsdWUifQ", encodeJSONBytes(json));

}

TEST(JWT_generation_dsa)
{
	// generate the keys
    AutoSeededRandomPool rnd;
	KeyPair* keypair = new DSAKeyPair();
    keypair->generateRandomKeys(&rnd);

	// and generate some tokens
	map<string, string> map1; // empty map should work

	JWT* t1 = parse(generate(keypair, &map1));
	CHECK_EQUAL(true, t1->checkSignature(keypair));


	map<string, string> map2; // empty map should work

    // We should also be able to deal with maps with real values in them
    map2["brown"] = "foxes";
    map2["red"] = "wine";

	JWT* t2 = parse(generate(keypair, &map2));
	CHECK_EQUAL(true, t2->checkSignature(keypair));
}

TEST(Map2Json)
{
    map<string, string> mymap;
    mymap["foo"] = "bar";
    mymap["baz"] = "baz?";

    json_t* jsonValue = map2json(&mymap);
}

int main(int argc, const char *argv[])
{
    return UnitTest::RunAllTests();
}
