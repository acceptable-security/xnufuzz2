# This file is responsible for parsing raw/syscall_logs.txt to generate data/examples.json to seed to the fuzzer
# It's also complete garbage.
# TODO - Rewrite it all

import csv
import json

# Yes, this is awful. But I don't care anymore. After an hour of working on this, I decided that python should live in a deep dark pit.
# It is an AWUFL language. I really hate it. I hate it so much I pray this is the last line of Python I ever have to write.
def idgaf_reader(csv_reader): 
	while True: 
		try: 
			yield next(csv_reader) 
		except csv.Error: 
			pass
		continue 
	return

list = open('raw/syscall_logs.txt').read().split('\n')
f = open('data/examples.json', 'w')

found_examples = {}

for example in list:
	if len(example) < 4:
		continue

	if example[:7] == "SYSCALL":
		continue

	if example[:6] == "dtrace":
		continue

	name = example[:example.index('(')]

	# TODO - Better arg parsing
	args = example[example.index('(')+1:example.index('\t')-2] # I don't use the ) here because idk if some of the returns have a ) in it, but it's less likely to have a \t in it
	args = repr(args.decode('string-escape'))[1:-1]
	nargs = []

	for l in idgaf_reader(csv.reader([args], delimiter=',', quotechar='"')):
		nargs = l

	if " 0x" in nargs:
		# I have no idea how it happens, just ignore it for now.
		continue

	nargs = map(str.strip, nargs)

	for i in xrange(len(nargs)):
		if nargs[i][:2] == "0x":
			try:
				nargs[i] = int(nargs[i], 16)
			except:
				pass

	if not name in found_examples:
		found_examples[name] = []

	found_examples[name].append(nargs)

f.write(json.dumps(found_examples, indent=4))
f.close()