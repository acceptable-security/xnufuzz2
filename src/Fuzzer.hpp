#ifndef _FUZZER_HPP
#define _FUZZER_HPP

#include "json.hpp"
#include "Syscall.hpp"

#include <random>
#include <stdint.h>
#include <vector>

using json = nlohmann::json;

typedef enum {
	FUZZ_ERROR,
	FUZZ_RANDOM,
	FUZZ_MUTATE,
	FUZZ_SCRIPT
} FuzzAction_t;

class Fuzzer {
private:
	// Syscall information
	json syscalls;
	json examples;
	bool haveExamples;

	// Data to be used during fuzzing
	int buf_index;
	std::vector<void*> buffers;
	std::vector<int> fds;

	// Things we need for random generation
	std::mt19937 rng;
	std::uniform_int_distribution<std::mt19937::result_type> int_dist;
	std::uniform_int_distribution<std::mt19937::result_type> char_dist;

	// Private initialization functions
	void addBuffers();
	void initFds();
	void initRandom();
	int getSyscallIndice(int number);

public:
	Fuzzer(const char* syscalls_path);
	Fuzzer(const char* syscalls_path, const char* examples_path);

	FuzzAction_t getAction(int syscall);
	Syscall run(int syscall);

	void* getRandomBuffer();
	uint64_t getRandomLong();
	uint32_t getRandomInt();
	uint8_t getRandomChar();

	void mutateBuffer(uint8_t* buffer, uint64_t size);
	void mutateLong(uint64_t* number);
	void mutateInt(uint32_t* number);
	void mutateChar(uint8_t* number);
};

#endif