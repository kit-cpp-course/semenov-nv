
#ifndef AES256_ENCRYPT_H
#define AES256_ENCRYPT_H


#include <iostream>
#include <cstdlib>

class Encrypt {
public:
	Encrypt(FILE* inp, FILE* out, std::string pass);
	int work();

private:
	FILE *input, *output;
	std::string pass;
};


#endif //AES256_ENCRYPT_H
