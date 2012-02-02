#include "string.h"

#include "jwt.h"
#include "utils.h"
#include "exceptions.h"

#include "cryptopp/dsa.h"
#include "cryptopp/osrng.h"

using namespace std;
using namespace jwtcpp;
using namespace CryptoPP;

namespace jwtcpp {

    JWT::JWT(const string& algorithm, json_t* payload, const string& signature,
             const string& signed_data)
    {
        this->algorithm = algorithm;
        this->payload = payload;
        this->signature = signature;
        this->signed_data = signed_data;
    }

    bool JWT::checkSignature(const string& key)
    {
        DSA::PublicKey publicKey;
        publicKey.Load(StringStore(key).Ref());

        DSA::Verifier verifier(publicKey);

        SignatureVerificationFilter svf(verifier);
        StringSource(this->signature +this->signed_data, true,
                     new Redirector(svf));

	    return svf.GetLastResult();
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

	string generate(const string& algorithm, const string& key,
                    map<string, string>* payloadMap)
    {
        // encode the algorithm in bytes
        json_t* jsonAlg = json_object();
        json_object_set(jsonAlg, "alg", json_string(algorithm.c_str()));
        string alg = encodeJSONBytes(jsonAlg);

        // loop on the payload map to create a json_object from it
        json_t* jsonPayload = json_object();

        if (payloadMap->size() > 0){
            map<string, string>::iterator iter;

            for(iter = payloadMap->begin(); iter != payloadMap->end(); iter++){
                json_object_set(jsonPayload, (*iter).first.c_str(),
                                json_string((*iter).second.c_str()));
            }

        }

        // encode the payload in bytes
        string payload = encodeJSONBytes(jsonPayload);

        // get a random number generator
        AutoSeededRandomPool rng;

        // sign the data with the key and the algorithm name.
        // XXX handle different algos
        DSA::PrivateKey privateKey;
        privateKey.Load(StringStore(key).Ref());

        DSA::Signer signer(privateKey);

        cout << alg + "." + payload << endl;

        string signature;
        StringSource(alg + "." + payload, true,
                     new SignerFilter(rng, signer, new StringSink(signature)));

        return alg + "." + payload + "." + signature;
    }
}
