#include "pch.h"
#include "Arg.h"
#include <random>
Arg::Arg(int count, char **args) {
	std::string tmp;
	this->error = false;
	for (int i = 1; i < count; i++) {
		tmp = readLine(args[i]);
		switch (i) {
		case 1:
			if (tmp == "-p") {
				pass = genPass();
				gen = true;
			}
			else {
				pass = tmp;
			}
			break;
		case 2:
			if (tmp == "-e") {
				type = true;
			}
			else if (tmp == "-d") {
				type = false;
			}
			break;
		case 3:
			input = tmp;
			break;
		case 4:
			output = tmp;
			break;
		default:
			error = true;
			break;
		}
		if (error) break;
	}
}

std::string Arg::readLine(char *line) {
	std::string tmp = "";
	for (int i = 0; line[i] != 0; i++) {
		tmp += line[i];
	}
	return tmp;
}

std::string Arg::genPass() {
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<int> dist(48, 126);
	std::string res = "";
	for (int i = 0; i < 32; ++i)
		res += (char)dist(mt);
	return res;
}