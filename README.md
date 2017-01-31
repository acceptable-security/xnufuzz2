# XNU Fuzz 2

## Introduction
This program was originally going to be based off of the original xnufuzz, however that idea was scrapped due to the fact that the original xnufuzz was so bare bones, there would be nothing left to keep. Also, having JSON parsing would be extremely helpful, so in the end a full rewrite was written. The goal of this is to create a fuzzer that is capable of thoroughly fuzzing XNU syscalls using both completely randomly generated arguments, and also mutated arguments from syscalls collected the dtrace.

## Prerequisites & Notices
As with any kernel fuzzing software, this can and will result in the loss of data, and it's even possible that this can impact the local network. As of right now, no protections are made to prevent this from shooting out network packets to random places in the internet, so please be conscious of these risks while running this software.
`raw/syscalls.master` is a listing of syscalls from `bsd/kern/syscalls.master` in the XNU source, and it can be regenerated using `syscallparser.py`.

## Setup
In order to completely download and compile the software you can run the following commands

	git clone https://github.com/block8437/xnufuzz2.git
	cd xnufuzz2
	g++ src/xnufuzz2.cpp -o xnufuzz2 -std=c++11

To generate a new `raw/syscall_logs.txt`, run `sudo dtruss -p ANYPID 2>> raw/syscall_logs.txt`. `ANYPID` should be substituted for any PID you would like to read the syscalls from. In my experience, running it with finder yields quite a bit of good results. Afterwards, run `syslogparser.py` to generate `data/examples.json`.

## Running
Simply running
	./xnufuzz2
Will suffice for running it in normal situations. No arguments are currently supported for fuzzing specific syscalls.