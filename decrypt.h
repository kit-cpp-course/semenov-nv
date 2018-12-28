#include <string>
#include <cstdio>
#include "AES.h"
// Реализация метода для дешифровки 
class Decrypt : AES {
public:
	Decrypt(FILE* inp, FILE* out, std::string pass);
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
