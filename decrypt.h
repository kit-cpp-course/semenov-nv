
#ifndef AES256_DECRYPT_H
#define AES256_DECRYPT_H

#include <string>
#include <cstdio>

class Decrypt {
public:
	Decrypt(FILE* inp, FILE* out, std::string pass);
	int work();

private:
	FILE *input, *output;
	std::string pass;
};


#endif //AES256_DECRYPT_H
