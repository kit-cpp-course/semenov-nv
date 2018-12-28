#include <iostream>
#include <cstdlib>
#include "AES.h"
// Реализация методов для шифрования
class Encrypt : AES {
public:
	Encrypt(FILE* inp, FILE* out, std::string pass);
	int work() override;

private:
	ByteArray::size_type start(const ByteArray::size_type plain_length, ByteArray &encrypted) override;
	ByteArray::size_type
		w_continue(const unsigned char *plain, ByteArray::size_type plain_length, ByteArray &encrypted) override;
	ByteArray::size_type end(ByteArray &encrypted) override;
	void check(ByteArray &encrypted) override;
	FILE *input, *output;
	std::string pass;
};
