#include "pch.h"
#include "Arg.h"
#include "encrypt.h"
#include "decrypt.h"

FILE *input, *output;
std::string pass;

int main(int argc, char **argv) {
	Arg a(argc, argv);
	if (a.error) {
		std::cout << "Missing arguments" << std::endl;
		printf("Usage: %s <-e|-d> <key> <input file> <output file>\n -p Generate new key\n", argv[0]);
		return 1;
	}
	pass = a.pass;
	input = fopen(a.input.c_str(), "r");
	output = fopen(a.output.c_str(), "w");
	if (a.gen) {
		std::cout << a.pass << std::endl;
	}
	int res = 0;
	if (a.type) {
		res = Encrypt(input, output, pass).work();
	}
	else {
		res = Decrypt(input, output, pass).work();
	}
	if (res == 1) {
		std::cout << "Can`t read input file";
	}
	else if (res == 2) {
		std::cout << "Can`t write to output file";
	}
	else {
		std::cout << "Procces complited";
	}
	return 0;
}