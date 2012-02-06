#include "keys.h"
#include <iostream>

#include "cryptopp/dsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"

using namespace std;
using namespace CryptoPP;

// DSA //

DSAKeyPair::DSAKeyPair(){
	this->algorithm = "DSA";
}


void KeyPair::load(const string& path){
	this->loadPublicKey(path);
	this->loadPrivateKey(path);
}

void DSAKeyPair::loadPublicKey(const string& filename){
	this->publicKey->Load(FileStore(filename.c_str()).Ref());
}

void DSAKeyPair::loadPrivateKey(const string& filename){
	this->privateKey->Load(FileStore(filename.c_str()).Ref());
}


void DSAKeyPair::write(const string& path){

}

string DSAKeyPair::sign(const string& data)
{
	// get a random number generator
	AutoSeededRandomPool rng;

	// sign the data with the key and the algorithm name.
	DSA::Signer signer(*this->privateKey);

	string signature;
	StringSource(data, true, new SignerFilter(rng, signer,
											  new StringSink(signature)));
	return signature;
}

bool DSAKeyPair::verify(const string& data, const string& signature){

	DSA::Verifier verifier(*this->publicKey);

	SignatureVerificationFilter svf(verifier);
	StringSource(signature + data, true, new Redirector(svf));

	return svf.GetLastResult();
}

// RSA
// XXX
