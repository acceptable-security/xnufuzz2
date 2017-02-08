#include "config.hpp"
#include "Syscall.hpp"
#include "Fuzzer.hpp"

#include <iostream>

void Syscall::addArg(uint64_t arg, int type) {
	this->args.push_back(arg);
	this->types.push_back(type);
}

void Syscall::debug() {
	std::cout << "syscall(" << std::dec << this->number;

	if ( this->args.size() > 0 ) {
		std::cout << ", ";
	}

	for ( int i = 0; i < this->args.size(); i++ ) {
		switch ( this->types[i] ) {
			case FUZZ_ARG_INT64:
			case FUZZ_ARG_INT32:
				std::cout << std::hex << "0x" << this->args[i];
				break;

			case FUZZ_ARG_SIZE:
				std::cout << std::dec << this->args[i];
				break;

			case FUZZ_ARG_FLOAT:
				std::cout << std::dec << this->args[i];
				break;

			case FUZZ_ARG_BUFFER: {
				std::cout << "\"";
				char* buffer = (char*) this->args[i];
				for ( int j = 0; j < BUFFER_SIZE; j++ ) {
					std::cout << "\\x" << std::hex << std::setfill('0') << std::setw(2) << (int) (buffer[j] & 0xFF);
				}
				std::cout << "\"";
				break;
			}
			case FUZZ_ARG_FILE: 
			case FUZZ_ARG_SOCKET:
				// ?????
				std::cout << std::dec << this->args[i];
				break;

			case FUZZ_ARG_UNKNOWN:
				break;
		}
 
		if ( i < this->args.size() - 1 ) {
			std::cout << ", ";
		}
	}

	std::cout << ");" << std::endl << std::flush;
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