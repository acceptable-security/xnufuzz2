#ifndef _SYSCALL_HPP
#define _SYSCALL_HPP

#include <cstdarg>
#include <stdint.h>
#include <vector>

class  Syscall {
private:
	int number;
	std::vector<uint64_t> args;

public:
	 Syscall(int number);	
	 Syscall(int number, int count, ...);

	 void addArg(uint64_t arg);
	 void execute();
};

#endif