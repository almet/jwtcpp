#include "jwt.h"
#include "utils.h"

using namespace std;
using namespace jwtcpp;

namespace jwtcpp {

    JWT::JWT(string algorithm, json_t* payload, string signature, string signed_data)
    {
        this->algorithm = algorithm;
        this->payload = payload;
        this->signature = signature;
        this->signed_data = signed_data;
    }

    bool JWT::checkSignature(string keyData)
    {

    }

    JWT* parse(string jwt)
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

        string algorithm = json_string_value(
				json_object_get(algorithm_json, "algo"));

        json_t* payload = decodeJSONBytes(raw_payload);

        JWT* obj = new JWT(algorithm, payload, signature, signed_data);
        return obj;
    }

	string generate(string algorithm, string key, map<string, string> payload)
    {
        return "";
    }

}
