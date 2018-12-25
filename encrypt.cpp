#include "encrypt.h"
#include "AES.h"
const long BUFFER_SIZE = 1024;

Encrypt::Encrypt(FILE *inp, FILE *out, std::string pass) {
	this->input = inp;
	this->output = out;
	this->pass = pass;
}

int Encrypt::work() {
	ByteArray key, enc;
	for (auto c : pass)
		key.push_back(c);

	if (input == 0) return 1;
	if (output == 0) return 2;


	AES aes(key);
	fseek(input, 0, SEEK_END);
	size_t file_len = ftell(input);
	fseek(input, 0, SEEK_SET);
	std::cout << "File size " << file_len << " bytes" << std::endl;
	aes.decrypt_start(file_len);

	enc.clear();
	aes.encrypt_start(file_len, enc);
	fwrite(enc.data(), enc.size(), 1, output);

	while (!feof(input)) {
		unsigned char buffer[BUFFER_SIZE];
		size_t buffer_len = fread(buffer, 1, BUFFER_SIZE, input);
		std::cout << "Read " << buffer_len << " bytes" << std::endl;
		if (buffer_len > 0) {
			enc.clear();
			aes.encrypt_continue(buffer, buffer_len, enc);
			fwrite(enc.data(), enc.size(), 1, output);
		}
	}

	enc.clear();
	aes.encrypt_end(enc);
	fwrite(enc.data(), enc.size(), 1, output);

	fclose(input);
	fclose(output);

	return 0;
}
