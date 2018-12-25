#ifndef AES_ARG_H
#define AES_ARG_H

#include <string>
// разбор агргументов командной строки 
class Arg {
public:
	Arg(int count, char** args);
	std::string readLine(char* line);
	std::string genPass();
	std::string pass, input, output;
	bool type;
	bool error;
	bool gen;
};


#endif //AES_ARG_H
