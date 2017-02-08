#ifndef _FUZZER_HPP
#define _FUZZER_HPP

#include "json.hpp"
#include "Syscall.hpp"

#include <random>
#include <stdint.h>
#include <vector>

using json = nlohmann::json;

typedef enum {
	FUZZ_ACTION_ERROR,
	FUZZ_ACTION_RANDOM,
	FUZZ_ACTION_MUTATE,
	FUZZ_ACTION_SCRIPT
} FuzzAction_t;

typedef enum {
	FUZZ_ARG_INT32,
	FUZZ_ARG_INT64,
	FUZZ_ARG_SIZE,
	FUZZ_ARG_FLOAT,
	FUZZ_ARG_BUFFER,
	FUZZ_ARG_FILE,
	FUZZ_ARG_SOCKET,
	FUZZ_ARG_UNKNOWN
} FuzzArgType_t;

class Fuzzer {
private:
	// Syscall information
	json syscalls;
	json examples;
	bool haveExamples;

	// Data to be used during fuzzing
	int buf_index;
	std::vector<void*> buffers;
	std::vector<int> file_fds;
	std::vector<int> socket_fds;

	// Things we need for random generation
	std::mt19937 rng;
	std::uniform_int_distribution<std::mt19937::result_type> int_dist;
	std::uniform_int_distribution<std::mt19937::result_type> char_dist;

	// Private initialization functions
	void addBuffers();
	void initFds();
	void initRandom();

	// Functions used internally for housekeeping 
	int getSyscallIndice(int number);
	FuzzAction_t getAction(int syscall);
	FuzzArgType_t getType(std::string type, std::string name);

public:
	Fuzzer(const char* syscalls_path);
	Fuzzer(const char* syscalls_path, const char* examples_path);

	int getSyscallCount() { return this->syscalls.size(); };
	Syscall fuzz(int syscall);

	template<typename T>
	T getRandom();

	template<typename T>
	void mutate(T* number);
	void mutateBuffer(uint8_t* buffer, uint64_t size);
};

#endif