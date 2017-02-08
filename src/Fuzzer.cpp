#include "config.hpp"
#include "Fuzzer.hpp"

#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>

Fuzzer::Fuzzer(const char* syscalls_path) {
	std::cout << "[+] Reading data/syscalls.json..." << std::endl;
	
	// Read and parse the data/syscalls.json file
	std::ifstream syscall_file(syscalls_path);
	
	if ( !syscall_file.good() ) {
		std::cerr << "[!] Unable to access the data/syscalls.json file!" << std::endl;
		return;
	}

	syscall_file >> this->syscalls;

	if ( syscalls.size() == 0 ) {
		std::cerr << "[!] Unable to load any syscalls!";
		return;
	}

	this->haveExamples = false;

	this->addBuffers();
	this->initFds();
	this->initRandom();
}

Fuzzer::Fuzzer(const char* syscalls_path, const char* examples_path) {
	std::cout << "[+] Reading " << syscalls_path << "..." << std::endl;
	
	// Read and parse the data/syscalls.json file
	std::ifstream syscall_file(syscalls_path);
	
	if ( !syscall_file.good() ) {
		std::cerr << "[!] Unable to access the data/syscalls.json file!" << std::endl;
		return;
	}

	syscall_file >> this->syscalls;

	if ( syscalls.size() == 0 ) {
		std::cerr << "[!] Unable to load any syscalls!";
		return;
	}

	std::cout << "[+] Attempting to load " << examples_path << std::endl;

	// Attempt to read & parse data/examples.json
	std::ifstream examples_file(examples_path);

	if ( examples_file.good() ) {
		std::cout << "[+] File successfully opened, reading..." << std::endl;
		examples_file >> this->examples;
		this->haveExamples = true;
	}
	else {
		this->haveExamples = false;
		std::cout << "[!] Unable to open the file. Continuing without exmaples..." << std::endl; 
	}

	this->addBuffers();
	this->initFds();
	this->initRandom();
}

void Fuzzer::addBuffers() {
	std::cout << "[+] Creating buffers" << std::endl;

	for ( int i = 0; i < BUFFER_COUNT; i++ ) {
		void* buffer = malloc(BUFFER_SIZE);
		memset(buffer, 0, BUFFER_SIZE);
		this->buffers.push_back(buffer);
	}
}

void Fuzzer::initFds() {
	std::cout << "[+] Creating file descriptors" << std::endl;

	this->file_fds.push_back(open("/dev/null", O_RDONLY));
	this->file_fds.push_back(open("/dev/null", O_RDWR));
	this->file_fds.push_back(open("/dev/null", O_WRONLY));
	this->file_fds.push_back(open("/bin/bash", O_RDONLY));
	this->file_fds.push_back(open("/etc/passwd", O_RDONLY));
	this->file_fds.push_back(open("/dev/urandom", O_RDONLY));
	this->file_fds.push_back(open("test.txt", O_RDWR));
	this->file_fds.push_back(open("test.txt", O_WRONLY));

	#define ADD(a) \
		this->socket_fds.push_back(socket(a, SOCK_STREAM, 0)); \
		this->socket_fds.push_back(socket(a, SOCK_DGRAM, 0)); \
		this->socket_fds.push_back(socket(a, SOCK_SEQPACKET, 0)); \

	ADD(AF_UNIX)
	ADD(AF_LOCAL)
	ADD(AF_INET)
	ADD(AF_INET6)
	ADD(AF_IPX)
	ADD(AF_APPLETALK)
}

void Fuzzer::initRandom() {
	std::cout << "[+] Creating random state" << std::endl;

	this->rng.seed(std::random_device()());
	this->int_dist = std::uniform_int_distribution<std::mt19937::result_type>(0, 0xFFFFFFFF);
	this->char_dist = std::uniform_int_distribution<std::mt19937::result_type>(0, 0xFF);

	srand(time(NULL));
}

int Fuzzer::getSyscallIndice(int number) {
	for ( int i = 0; i < this->syscalls.size(); i++ ) {
		int _n = this->syscalls[i]["number"];

		if ( _n == number ) {
			return i;
		}
	}

	return -1;
}

FuzzAction_t Fuzzer::getAction(int number) {
	int indice = this->getSyscallIndice(number);

	if ( indice == -1 ) {
		return FUZZ_ACTION_ERROR;
	}

	std::string name = this->syscalls[indice]["funcname"];

	if ( examples.find(name) == examples.end() ) {
		return FUZZ_ACTION_RANDOM;
	}
	else {
		switch ( rand() % 3 ) {
			case 0:
			case 1:
				return FUZZ_ACTION_MUTATE;
			case 2:
				return FUZZ_ACTION_RANDOM;
			default: return FUZZ_ACTION_MUTATE;
		}
	}
}

FuzzArgType_t Fuzzer::getType(std::string type, std::string name) {
	if ( name.compare(0, 2, "fd") == 0 ) {
		return FUZZ_ARG_FILE;
	}
	else if ( name == "s" ) {
		return FUZZ_ARG_SOCKET;
	}
	else {
		if ( type == "int" || type == "uint" || type == "u_int" || type == "int32_t" || type == "uint32_t" ||
			 type == "gid_t" || type == "off_t" || type == "sae_connid_t" || type == "mach_port_name_t" || type == "unsigned int" || 
			 type == "idtype_t" || type == "uid_t" || type == "pid_t" ) {
			return FUZZ_ARG_INT32;
		}
		else if ( type == "user_size_t" || type == "size_t" || type == "socklen_t" || type == "user_ssize_t" ) {
			return FUZZ_ARG_SIZE;
		}
		else if ( type == "u_long" || type == "long" || type == "int64_t" || type == "id_t" || type == "uint64_t" || type == "key_t" || type == "semun_t" || type == "sigset_t" ) {
			return FUZZ_ARG_INT64;
		}
		else if ( type.back() == '*' || type == "user_addr_t" || type == "caddr_t" ) {
			return FUZZ_ARG_BUFFER;
		}
		else {
			return FUZZ_ARG_UNKNOWN;
		}
	}
}



// =======================
template<>
void* Fuzzer::getRandom() {
	if ( this->buf_index >= this->buffers.size() ) {
		this->addBuffers();
	}

	char* buffer = (char*) this->buffers[this->buf_index++];

	switch ( rand() % 3 ) {
		case 0:
			memset(buffer, this->char_dist(this->rng), BUFFER_SIZE);
			break;

		case 1:
		case 2:
			for ( int i = 0; i < BUFFER_SIZE; i++ ) {
				buffer[i] = this->char_dist(this->rng);
			}
			break;
	}

	return (void*) buffer;
}

template<>
uint64_t Fuzzer::getRandom() {
	switch ( rand() % 5 ) {
		case 0:
		case 1: {
			long a = (long) int_dist(rng);
			long b = (long) int_dist(rng);
		
			return (a << 32) + b;
		}

		case 2:
			return -1;

		case 3:
			return 1;

		default:
			return 0;
	}
}

template<>
uint32_t Fuzzer::getRandom() {
	switch ( rand() % 5 ) {
		case 0:
		case 1:
			return this->int_dist(this->rng);
		case 2:
			return -1;
		case 3:
			return 1;
		default:
			return 0;
	}
}

template<>
uint8_t Fuzzer::getRandom() {
	switch ( rand() % 5 ) {
		case 0:
		case 1:
		case 2:
			return this->char_dist(this->rng);
		case 3:
			return -1;
		case 4:
			return 1;
		default:
			return 0;
	}
}

// Instead of this deciding how many times to mutate the variables, this should be called for the
// amount of times the variables should be mutated.
template<>
void Fuzzer::mutate(uint64_t* number) {
	int random_pos = rand() % 64;

	switch ( rand() % 5 ) {
		case 0:
			*number = (*number) ^ (1 << random_pos);
			break;

		case 1:
			*number = (*number) + 1;
			break;

		case 2:
			*number = (*number) - 1;
			break;

		case 3:
			*number = (*number) >> 1;
			break;

		case 4:
			*number = ((*number) << 1) & 0xFFFFFFFFFFFFFFFF;
			break;
	}
}

template<>
void Fuzzer::mutate(uint32_t* number) {
	int random_pos = rand() % 32;

	switch ( rand() % 5 ) {
		case 0:
			*number = (*number) ^ (1 << random_pos);
			break;

		case 1:
			*number = (*number) + 1;
			break;

		case 2:
			*number = (*number) - 1;
			break;

		case 3:
			*number = (*number) >> 1;
			break;

		case 4:
			*number = ((*number) << 1) & 0xFFFFFFFF;
			break;
	}
}

template<>
void Fuzzer::mutate(uint8_t* number) {
	int random_pos = rand() % 8;

	switch ( rand() % 5 ) {
		case 0:
			*number = (*number) ^ (1 << random_pos);
			break;

		case 1:
			*number = (*number) + 1;
			break;

		case 2:
			*number = (*number) - 1;
			break;

		case 3:
			*number = (*number) >> 1;
			break;

		case 4:
			*number = ((*number) << 1) & 0xFF;
			break;
	}
}

void Fuzzer::mutateBuffer(uint8_t* buffer, uint64_t size) {
	int index = rand() % size;

	switch ( rand() % 3 ) {
		case 0:
			this->mutate<uint8_t>(&buffer[index]);
			break;

		case 1:
			buffer[index] = this->getRandom<uint8_t>();
			break;

		case 2:
			buffer[index] = ~buffer[index];
			break;
	}
}

Syscall Fuzzer::fuzz(int number) {
	this->buf_index = 0;
	Syscall sys = Syscall(number);

	int indice = this->getSyscallIndice(number);

	if ( indice == -1 ) {
		sys.invalidate();
		return sys;
	}

	FuzzAction_t action = this->getAction(number);
	int argc = this->syscalls[indice]["args"].size();

	if ( argc == 0 ) {
		sys.invalidate();
		return sys;
	}

	switch ( action ) {
		case FUZZ_ACTION_ERROR: break;
		case FUZZ_ACTION_RANDOM: {
			for ( int i = 0; i < argc; i++ ) {
				std::string arg = this->syscalls[indice]["args"][i]["name"];
				std::string type = this->syscalls[indice]["args"][i]["type"];

				switch ( this->getType(type, arg) ) {
					case FUZZ_ARG_INT32:
						sys.addArg((uint64_t) this->getRandom<uint32_t>(), FUZZ_ARG_INT32);
						break;

					case FUZZ_ARG_BUFFER:
						sys.addArg((uint64_t) this->getRandom<void*>(), FUZZ_ARG_BUFFER);
						break;

					// TODO - Adapting this to make sense for each type would be helpful.
					case FUZZ_ARG_SIZE:
						sys.addArg(BUFFER_SIZE, FUZZ_ARG_SIZE); 
						break;

					case FUZZ_ARG_FILE:
						sys.addArg((uint64_t) this->file_fds[rand() % this->file_fds.size()], FUZZ_ARG_FILE);
						break;

					case FUZZ_ARG_SOCKET:
						sys.addArg((uint64_t) this->socket_fds[rand() % this->file_fds.size()], FUZZ_ARG_SOCKET);
						break;

					case FUZZ_ARG_INT64:
					default:
						sys.addArg(this->getRandom<uint64_t>(), FUZZ_ARG_INT64);	
						break;
				}
			}
		}

		case FUZZ_ACTION_MUTATE: {
			std::string func = this->syscalls[indice]["funcname"];

			for ( int i = 0; i < argc; i++ ) {
				std::string arg = this->syscalls[indice]["args"][i]["name"];
				std::string type = this->syscalls[indice]["args"][i]["type"];
				json allexamples = this->examples[func];

				if ( allexamples.size() < argc ) {
					// TODO - Handle this
					sys.invalidate();
					return sys;
				}

				json example = allexamples[rand() % allexamples.size()];
				std::cout << func << "<" << type << ">" << std::endl;

				switch ( this->getType(type, arg) ) {
					case FUZZ_ARG_INT32: {
						uint32_t val = example[i];
						this->mutate<uint32_t>(&val);
						sys.addArg((uint64_t) val, FUZZ_ARG_INT32);
							break;
					}

					case FUZZ_ARG_BUFFER: {
						switch ( example[i].type() ) {
							case json::value_t::string: {
								const char* val = (example[i].get<std::string>()).c_str();
								this->mutateBuffer((uint8_t*) val, BUFFER_SIZE);
								sys.addArg((uint64_t) val, FUZZ_ARG_BUFFER);
								break;
							}
							default:
								sys.addArg((uint64_t) this->getRandom<void*>(), FUZZ_ARG_BUFFER);
								break;
						}
					}

					// TODO - Adapting this to make sense for each type would be helpful.
					case FUZZ_ARG_SIZE:
						sys.addArg(BUFFER_SIZE, FUZZ_ARG_SIZE); 
						break;

					case FUZZ_ARG_FILE:
						sys.addArg((uint64_t) this->file_fds[rand() % this->file_fds.size()], FUZZ_ARG_FILE);
						break;

					case FUZZ_ARG_SOCKET:
						sys.addArg((uint64_t) this->socket_fds[rand() % this->file_fds.size()], FUZZ_ARG_SOCKET);
						break;

					case FUZZ_ARG_INT64:
					default:
						uint64_t val = example[i];
						this->mutate(&val);
						sys.addArg(val, FUZZ_ARG_INT64);	
						break;
				}
			}
		}

		case FUZZ_ACTION_SCRIPT: {
			// TODO -
			break;
		}
	}

	return sys;
}