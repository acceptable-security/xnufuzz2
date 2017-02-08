#ifndef _SYSCALL_HPP
#define _SYSCALL_HPP

#include <cstdarg>
#include <stdint.h>
#include <vector>

class  Syscall {
private:
	int number = -1;
	std::vector<uint64_t> args;
	std::vector<int> types;

public:
	 Syscall(int number) : number(number) {};

	 void addArg(uint64_t arg, int type);
	 void execute();
	 void debug();
	 void invalidate() { this->number = -1; };

	 int getNumber() { return this->number; };
};

#endif