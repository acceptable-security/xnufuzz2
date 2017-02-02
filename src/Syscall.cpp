#include "Syscall.hpp"

Syscall::Syscall(int number) {
	this->number = number;
}

Syscall::Syscall(int number, int count, ...) {
	this->number = number;

	va_list args;
	va_start(args, count);

	for ( int i = 0; i < count; i++ ) {
		this->args.push_back(va_arg(args, uint64_t));
	}

	va_end(args);
}

void Syscall::addArg(uint64_t arg) {
	this->args.push_back(arg);
}

void Syscall::execute() {
	switch ( this->args.size() ) {
		case 1:
			syscall(number, args[0]);
			break;
		case 2:
			syscall(number, args[0], args[1]);
			break;
		case 3:
			syscall(number, args[0], args[1], args[2]);
			break;
		case 4:
			syscall(number, args[0], args[1], args[2], args[3]);
			break;
		case 5:
			syscall(number, args[0], args[1], args[2], args[3], args[4]);
			break;
		case 6:
			syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]);
			break;
		case 7:
			syscall(number, args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
			break;
		case 8:
			syscall(number, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
			break;

		default: return;
	}
}