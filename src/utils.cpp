#include "cryptopp/base64.h"
#include <iostream>

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
	int pos = out.find("=");
	if (pos != -1){
		out.erase(pos);
	}
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

json_t* map2json(map<string, string>* data){
	// loop on the payload map to create a json_object from it
	json_t* jsonPayload = json_object();

	if (data->size() > 0){
		map<string, string>::iterator iter;

		for(iter = data->begin(); iter != data->end(); iter++){
			json_object_set(jsonPayload, (*iter).first.c_str(),
							json_string((*iter).second.c_str()));
		}

	}
	return jsonPayload;
}
}
