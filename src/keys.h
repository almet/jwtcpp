#ifndef keysh
#define keysh

#include <iostream>
#include "cryptopp/dsa.h"
#include "cryptopp/osrng.h"

/**
 * Defines utility wrappers to CryptoPP key mechanisms (DSA and RSA).
 *
 * As CryptoPP does not defines an unified interface to them, this is provided
 * by the following classes.
 * */

using namespace std;
using namespace CryptoPP;

class KeyPair
{
	public:
		string algorithm;
		virtual string sign(const string& data) = 0;
		virtual bool verify(const string& data, const string& signature) = 0;
		virtual void write(const string& path) = 0;
		virtual void loadPublicKey(const string& path) = 0;
		virtual void loadPrivateKey(const string& path) = 0;
		virtual void generateRandomKeys(AutoSeededRandomPool* rnd) = 0;

		void load(const string& path);
};

class DSAKeyPair : public KeyPair
{
	public:
        DSA::PublicKey* publicKey;
        DSA::PrivateKey* privateKey;

		DSAKeyPair();

		string sign(const string& data);
		bool verify(const string& data, const string& signature);
		void loadPublicKey(const string& path);
		void loadPrivateKey(const string& path);
		void write(const string& path);
		void generateRandomKeys(AutoSeededRandomPool* rnd);
};
#endif
