#include "decrypt.h"
#include "AES.h"
#include <iostream>
#include <ctime>
const long BUFFER_SIZE = 1024;

Decrypt::Decrypt(FILE *inp, FILE *out, std::string pass) {
	this->input = inp;
	this->output = out;
	this->pass = pass;
}

int Decrypt::work() {
	ByteArray key, dec;
	size_t file_len;

	srand(time(0));
	for (auto c : pass) {
		key.push_back(c);
	}
	if (input == 0) return 1;
	if (output == 0) return 2;

	AES aes(key);
	fseek(input, 0, SEEK_END);
	file_len = ftell(input);
	fseek(input, 0, SEEK_SET);
	std::cout << "File size " << file_len << " bytes" << std::endl;
	aes.decrypt_start(file_len);

	while (!feof(input)) {
		unsigned char buffer[BUFFER_SIZE];
		size_t buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
		std::cout << "Read " << buffer_len << " bytes" << std::endl;
		if (buffer_len > 0) {
			dec.clear();
			aes.decrypt_continue(buffer, buffer_len, dec);
			fwrite(dec.data(), dec.size(), 1, output);
		}
	}

	dec.clear();
	aes.decrypt_end(dec);
	fwrite(dec.data(), dec.size(), 1, output);

	fclose(input);
	fclose(output);

	return 0;
}
