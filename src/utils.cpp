#include "cryptopp/base64.h"

extern "C" {
#include "jansson.h"
}

using namespace CryptoPP;
using namespace std;

namespace jwtcpp {

string decodeBase64(string value){
    string out;

    // Add some chars to the input so it works as expected
    int pad = value.size() % 4;

    if(pad == 2){
        value += "==";
    } else if (pad == 3){
        value += "=";
    }

    StringSource(value, true, new Base64Decoder(new StringSink(out))); 
    return out;
}

string encodeBase64(string value){
    string out;
    StringSource(value, true, new Base64Encoder(new StringSink(out))); 

    // remove the extra "=" appended by the base64 convertion
    out.erase(out.find("="));
    return out;
}

json_t* decodeJSONBytes(string input){
    string decoded = decodeBase64(input.c_str());
    json_error_t error;
    json_t* json = json_loads(decoded.c_str(), 0, &error);

    if (!json){
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        // XXX should we throw an exception here?
    }

    return json;
}

string encodeJSONBytes(json_t* input){
    return encodeBase64((string) json_dumps(input, 0));
}

}
