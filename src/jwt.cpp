#include "string.h"

#include "jwt.h"
#include "utils.h"

using namespace std;
using namespace jwtcpp;

namespace jwtcpp {

    JWT::JWT(const string& algorithm, json_t* payload, const string& signature,
             const string& signed_data)
    {
        this->algorithm = algorithm;
        this->payload = payload;
        this->signature = signature;
        this->signed_data = signed_data;
    }

    bool JWT::checkSignature(KeyPair* keypair)
    {
        return keypair->verify(this->signed_data, this->signature);
    }

    JWT* parse(const string& jwt)
    {
        size_t pos;

        // extracting the algorithm, payload, signature and data
        char* tok = strtok((char*) jwt.c_str(), ".");
        string raw_algorithm = (string) tok;

        tok = strtok(NULL, ".");
        string raw_payload = (string) tok;

        tok = strtok(NULL, ".");
        string signature = (string) tok;

        string signed_data = raw_algorithm + "." + raw_payload;

        // decode json values for the algorithm and the payload
        json_t* algorithm_json = decodeJSONBytes(raw_algorithm);

        // check that the "alg" parameter is present. If not, throw an
        // exception
        json_t* algorithm_ = json_object_get(algorithm_json, "alg");
        if (algorithm_ == NULL){
            ParsingError e;
            throw e;
        }

        string algorithm = json_string_value(algorithm_);

        json_t* payload = decodeJSONBytes(raw_payload);

        JWT* obj = new JWT(algorithm, payload, signature, signed_data);
        return obj;
    }

	string generate(KeyPair* keypair, map<string, string>* payloadMap)
    {
        json_t* jsonPayload = map2json(payloadMap);
        string output = generate(keypair, jsonPayload);
        free(jsonPayload);
        return output;
    }

    string generate(KeyPair* keypair, json_t* jsonPayload)
    {
        // encode the algorithm in bytes
        json_t* jsonAlg = json_object();
        json_object_set(jsonAlg, "alg", json_string(keypair->algorithm.c_str()));
        string alg = encodeJSONBytes(jsonAlg);

        // encode the payload in bytes
        string payload = encodeJSONBytes(jsonPayload);
        string signature = keypair->sign(alg + "." + payload);

        return alg + "." + payload + "." + signature;
    }
}
