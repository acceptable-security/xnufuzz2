/**
 * xnufuzz2 by Brian Smith
 * Created January 29th, 2017
 */

#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <random>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <vector>

#include "json.hpp"

#define BUFFER_SIZE 768

using json = nlohmann::json;

std::vector<void*> buffers; // Some useful buffers
std::vector<int> fds; // Some real file descriptors to play with.

// Stupid intro to warn people about this
void cutsie_intro() {
	std::cout << "[+] This program can and likely will cause extreme harm to your computer. Loss of data, life and limb should be expected." << std::endl;
	std::cout << "[+] I am not responsible for any damage this program causes." << std::endl;
}

// Fuzz a syscall given it's arguments and example call of it to use for mutation.
void fuzz_with_example(int num, json* args, json* example) {
	std::mt19937 rng;
	rng.seed(std::random_device()());
	std::uniform_int_distribution<std::mt19937::result_type> int_dist(0, INT_MAX);
	std::uniform_int_distribution<std::mt19937::result_type> char_dist(0, 0xFF);

}

// This was gracefully stolen from some stackoverflow answer.
struct HexCharStruct {
	unsigned char c;
	HexCharStruct(unsigned char _c) : c(_c) { }
};

inline std::ostream& operator<<(std::ostream& o, const HexCharStruct& hs) {
	return (o << std::hex << (int)hs.c);
}

inline HexCharStruct hex(unsigned char _c) {
	return HexCharStruct(_c);
}

typedef enum {
	INT32,
	INT64,
	BUFFER
} fuzz_types_t;

// Fuzz a syscall given it's arguments
void fuzz_normal(int num, json* _args) {
	std::mt19937 rng;
	rng.seed(std::random_device()());
	std::uniform_int_distribution<std::mt19937::result_type> int_dist(0, INT_MAX);
	std::uniform_int_distribution<std::mt19937::result_type> char_dist(0, 0xFF);
	
	std::vector<uint64_t> args;
	std::vector<fuzz_types_t> types;

	int bufcount = 0;

	for ( int i = 0; i < _args->size(); i++ ) {
		auto arg = (*_args)[i];
		std::string name = arg["name"];
		std::string type = arg["type"];

		if ( (name.compare(0, 2, "fd") == 0 && fds.size() > 0) && (rand() % 2) == 1 ) {
			args.push_back(fds[rand() % fds.size()]);
			types.push_back(INT32);
		}
		else {
			if ( type == "int" || type == "uint" || type == "u_int" || type == "int32_t" || type == "uint32_t" || type == "gid_t" || type == "off_t" || type == "sae_connid_t" || type == "mach_port_name_t" || type == "unsigned int" || type == "idtype_t" ) {
				args.push_back(int_dist(rng));
				types.push_back(INT32);
			}
			else if ( type == "user_size_t" || type == "size_t" || type == "socklen_t" || type == "user_ssize_t" ) {
				args.push_back(int_dist(rng));
				types.push_back(INT32);
			}
			else if ( type == "u_long" || type == "long" || type == "int64_t" || type == "id_t" || type == "uint64_t" || type == "key_t" || type == "semun_t" || type == "sigset_t" ) {
				long a = (long) int_dist(rng);
				long b = (long) int_dist(rng);
				args.push_back((a << 32) + b);
				types.push_back(INT64);
			}
			else if ( type == "uid_t" || type == "pid_t") {
				args.push_back(int_dist(rng));
				types.push_back(INT32);
			}
			else if ( type.back() == '*' || type == "user_addr_t" || type == "caddr_t" ) {
				char* buf = (char*) buffers[bufcount++];

				for ( int j = 0; j < BUFFER_SIZE; j++ ) {
					buf[j] = char_dist(rng);
				}

				args.push_back((uint64_t) buf);
				types.push_back(BUFFER);

				if ( i < _args->size() - 1 && rand() % 2 == 1 ) {
					json next_arg = (*_args)[i + 1];
					std::string next_name = next_arg["name"];
					std::string next_type = next_arg["type"];
					std::string ending = "size";

					if ( (next_type == "user_size_t" || next_type == "size_t" || next_type == "user_ssize_t") && (rand() % 2) == 1 ) {
						args.push_back(BUFFER_SIZE);
						types.push_back(INT32);
						i++;
						continue;
					}
				}
			}
			else {
				long a = (long) int_dist(rng);
				long b = (long) int_dist(rng);
				args.push_back((a << 32) + b);
				types.push_back(INT64);
			}
		}
	}

	std::cout << "syscall(" << num << ", " << std::hex;

	for ( int i = 0; i < args.size(); i++ ) {
		if ( types[i] == BUFFER ) {
			char* buffer = (char*) args[i];

			std::cout << "\"";
			for ( int j = 0; j < BUFFER_SIZE; j++ ) {
				std::cout << "\\x" << std::hex << std::setfill('0') << std::setw(2) << hex(buffer[j]);
			}
			std::cout << "\"";
		}
		else {
			std::cout << args[i];
		}
		if ( i < _args->size() - 1 ) {
			std::cout << ", ";
		}
	}

	std::cout << ")" << std::endl << std::dec << std::flush;

	usleep(5);

	switch ( _args->size() ) {
		case 1:
			syscall(num, args[0]);
			break;
		case 2:
			syscall(num, args[0], args[1]);
			break;
		case 3:
			syscall(num, args[0], args[1], args[2]);
			break;
		case 4:
			syscall(num, args[0], args[1], args[2], args[3]);
			break;
		case 5:
			syscall(num, args[0], args[1], args[2], args[3], args[4]);
			break;
		case 6:
			syscall(num, args[0], args[1], args[2], args[3], args[4], args[5]);
			break;
		case 7:
			syscall(num, args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
			break;
		case 8:
			syscall(num, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
			break;

		default: return;
	}
}

// Initialize buffers and file descriptors that the fuzzer could use
void init_fuzzer() {
	std::cout << "[+] Creating real file descriptors..." << std::endl;
	fds.push_back(open("/dev/null", O_RDONLY));
	fds.push_back(open("/bin/bash", O_RDONLY));
	fds.push_back(open("/etc/passwd", O_RDONLY));
	fds.push_back(open("/dev/random", O_RDONLY));

	std::cout << "[+] Creating real buffers..." << std::endl;

	for ( int i = 0; i < 10; i++ ) {
		buffers.push_back(malloc(sizeof(char) * BUFFER_SIZE));
	}
}

int main(int argc, char* argv[]) {
	cutsie_intro();

	std::cout << "[+] Reading data/syscalls.json..." << std::endl;
	
	// Read and parse the data/syscalls.json file
	std::ifstream syscall_file("data/syscalls.json");
	json syscall;
	
	if ( !syscall_file.good() ) {
		std::cerr << "[!] Unable to access the data/syscalls.json file!" << std::endl;
		return 1;
	}

	syscall_file >> syscall;

	if ( syscall.size() == 0 ) {
		std::cerr << "[!] Unable to load any syscalls!";
		return 1;
	}

	std::cout << "[+] Attempting to load data/examples.json" << std::endl;

	// Attempt to read & parse data/examples.json
	std::ifstream examples_file("data/examples.json");
	json examples;
	bool have_examples = false;

	if ( examples_file.good() ) {
		std::cout << "[+] File successfully opened, reading..." << std::endl;
		examples_file >> examples;
		have_examples = true;
	}
	else {
		std::cout << "[!] Unable to open the file. Continuing without exmaples..." << std::endl; 
	}

	init_fuzzer();

	std::cout << "[+] Have " << syscall.size() << " syscalls loaded." << std::endl;
	std::cout << "[+] Prepare for tactical fuzzing..." << std::endl;

	srand(time(NULL));

	while ( true ) {
		// Pick a random syscall
		int num = rand() % syscall.size(); 
		json info = syscall[num];

		// This should never happen
		if ( info == nullptr ) {
			std::cerr << "[+] Found a strange syscall " << num <<"!" << std::endl;
			return 1;
		}

		json args = info["args"];
		json example;

		// If theres an example to be used, half the time pick a random one and fuzz with it, else just fuzz normally.
		if ( have_examples && examples.find(info["funcname"]) != examples.end() && rand() % 2 == 1 ) {
			std::string func_name = info["funcname"];
			json all_examples = examples[func_name];
			example = all_examples[rand() % all_examples.size()];

			fuzz_with_example(info["number"], &args, &example);
		}
		else {
			fuzz_normal(info["number"], &args);
		}
	}

	std::cout << "[+] Something strange happened." << std::endl;
	return 0;
}