#include "string.h"
#include "unittest++/UnitTest++.h"
#include "utils.h"
#include <iostream>

extern "C" {
#include "jansson.h"
}

using namespace std;
using namespace jwtcpp;

/**
 * This file contains tests for the JWT generation and parsing.
 **/

TEST(DecodeBase64)
{
	// extra == should be added on the fly
    string decoded = jwtcpp::decodeBase64("eyJ0ZXN0IjogInllYWgifQ");
	CHECK_EQUAL("{\"test\": \"yeah\"}", decoded);
}

TEST(EncodeBase64)
{
	// when encoding, the extra "=" should be removed
    string base64json = jwtcpp::encodeBase64("{\"test\": \"yeah\"}");
	CHECK_EQUAL("eyJ0ZXN0IjogInllYWgifQ", base64json);
}

TEST(DecodeJSONBytes)
{
	// An encoded b64 encoded JSON value should decode successfully
    json_t* root = jwtcpp::decodeJSONBytes("eyJ0ZXN0IjogInllYWgifQ");
	// check that the returned object is a json object. It should contain the
	// "test" chain.
    CHECK_EQUAL("yeah", json_string_value(json_object_get(root, "test")));
}

TEST(EncodeJSONBytes)
{
	json_error_t* errors;
	json_t* json = json_loads("{\"key\":\"value\"}", 0, errors);
	CHECK_EQUAL("eyJrZXkiOiAidmFsdWUifQ", jwtcpp::encodeJSONBytes(json));
}

TEST(JWT_Extraction)
{
	// We should be able to load a JSON Web Token. This means being able to
	// extract the information from the token.
}

TEST(JWT_Signature)
{
	// We should also be able to check that the certificates bundled in the
	// token are valid for it.
}

TEST(Load_Algorithm)
{
	// JWT handle a bunch of algorithms. We should be able to load the right
	// one depending on some text.
	// In case of a failure, we should throw an exception
}

int main(int argc, const char *argv[])
{
    return UnitTest::RunAllTests();
}
