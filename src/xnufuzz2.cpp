#include "cmdline.hpp"
#include "Fuzzer.hpp"
#include "Syscall.hpp"


#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
	cmdline::parser parser;

	parser.add<int>("count", 'c', "amount of syscalls to generate", false, 0);
	parser.add<int>("specific", 's', "specific syscall to fuzz", false, -1);
	parser.add<std::string>("syscalls", 'p', "path to syscalls", false, "data/syscalls.json");
	parser.add<std::string>("examples", 'e', "path to examples", false, "data/examples.json");
	parser.add<bool>("dry", 'd', "dry run or not", false, false);

	parser.parse_check(argc, argv);


	Fuzzer fuzz = Fuzzer(parser.get<std::string>("syscalls").c_str(), 
						 parser.get<std::string>("examples").c_str());

	int specific = parser.get<int>("specific");
	bool dry = parser.get<bool>("dry");

	std::cout << "[+] Finished initializing fuzzer." << std::endl;
	std::cout << "[+] Notice: I am not liable for any damage done to your computer." << std::endl;

	if ( specific > -1 ) {
		// TODO - Is there a better loop we can do?
		for ( int i = 0; parser.get<int>("count") == 0 || i < parser.get<int>("count"); i++ ) {
			Syscall call = fuzz.fuzz(specific);

			if ( call.getNumber() == -1 ) {
				i--; // Don't count.
				std::cerr << "[!] Failed to fuzz syscall " << std::dec << specific << std::endl;
				break;
			}

			call.debug();

			if ( !dry ) {
				usleep(5);
				call.execute();
			}
		}
	}
	else {
		for ( int i = 0; parser.get<int>("count") == 0 || i < parser.get<int>("count"); i++ ) {
			int number = rand() % fuzz.getSyscallCount();
			Syscall call = fuzz.fuzz(number);

			if ( call.getNumber() == -1 ) {
				i--; // Don't count.
				continue;
			}

			call.debug();

			if ( !dry ) {
				usleep(5);
				call.execute();
			}
		}
	}

	return 0;
}