#define _CRT_SECURE_NO_WARNINGS 
#include "pch.h"
#include <iostream> 
#include <ctime> 
#include <string> 
#include "AES.h" 
#include "Arg.h"
const long BUFFER_SIZE = 1024;

int decrypt();
int encrypt();
FILE *input, *output;
std::string pass;

int main(int argc, char **argv) {
	int i;
	Arg a(argc, argv);
	if (a.error) {
		std::cout << "Missing arguments" << std::endl;
		printf_s("Usage: %s <-e|-d> <key> <input file> <output file>\n -p Generate new key\n", argv[0]);
		return 1;
	}
	pass = a.pass;
	input = fopen(a.input.c_str(), "r");
	output = fopen(a.output.c_str(), "w");
	if (a.gen)
		std::cout << a.pass << std::endl;
	int res = 0;
	if (a.type)
		res = encrypt();
	else
		res = decrypt();
	if (res == 1)
		std::cout << "Can`t read input file";
	else if (res == 2)
		std::cout << "Can`t write to output file";
	else
		std::cout << "Procces complited";
	return 0;
}

int encrypt() {
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

int decrypt() {
	ByteArray key, dec;
	size_t file_len;

	srand(time(0));
	for (auto c : pass)
		key.push_back(c);

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