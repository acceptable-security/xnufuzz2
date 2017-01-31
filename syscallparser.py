# This file is responsible for taking a raw syscalllist.txt and parsing it into a JSON readable format, while also
# weeding out any unnecesary syscalls (i.e syscalls that don't take input, or don't exist/won't run)

import json

syscalls = open('raw/syscalls.master').read().split('\n')[1:]
formatted = open('data/syscalls.json', 'w')
already_parsed = [131, 73, 422, 310, 131, 401, 301, 296, 410, 306, 111, 305, 1, 307, 361] # This way they'll be ignored.
total_count = 0
total = []
types = []
max_len = 0

for syscall in syscalls:
	syscall = syscall.strip()

	# Try to weed out any bad lines
	if len(syscall) == 0 or syscall[0] == ";" or syscall[0] == "#":
		continue

	# I fucking hate you Apple
	syscall = syscall.replace('       ', '\t')
	syscall = syscall.replace('     ', '\t')
	syscall = syscall.replace('socklen_t\t', 'socklen_t ')
	syscall = syscall.replace('\t\tALL', '\t')
	syscall = syscall.replace(' ALL', '\tALL')
	syscall = syscall.replace('ALL ', 'ALL')
	syscall = syscall.replace('\t\t', '\t')
	syscall = syscall.replace('\t}', ' }')
	syscall = syscall.replace('} \t{', '} {')
	syscall = syscall.replace('}\t{', '} {')
	syscall = syscall.replace('int\t', 'int ')
	syscall = syscall.replace('struct\t', 'struct ')
	syscall = syscall.replace(' AUE', '\tAUE')

	syscall = syscall.split('\t')
	
	if not "ALL" in syscall:
		number, name, code = syscall
	else:
		number, name, _, code = syscall
	# Seriously, I fucking hate you Apple.
	
	# TODO - Some syscalls actually can run that have this. Maybe try and read those?
	if "nosys" in code:
		continue

	code = code.strip()[1:-1] # Remove spaces and brackets
	args = map(str.strip, code[code.index('(')+1 : code.index(')')].split(',')) # Cut the args out and split by the coma
	funcname = code[code.index(' ', 2)+1 : code.index('(')] # Rip the function name out
	number = int(number.strip())

	# Don't take any duplicates. This is usually indicative of a #ifdef ... #else ... #endif statement.
	if number in already_parsed:
		continue

	already_parsed.append(number)

	# Any syscall that can't take user input isn't worth our time.
	if (len(args) == 1 and args[0] == "void") or len(args) == 0:
		continue

	nargs = []

	for arg in args:
		arg = arg.strip().replace('  ', ' ')

		ctype = ""
		name = ""

		# If there is a prefix, include that in the type
		if "struct" in arg or "unsigned" in arg or "const" in arg:
			n = 2
			if "const struct" in arg:
				n = 3

			ctype, name = ' '.join(arg.split(' ')[:n]), arg.split(' ')[n:][0]
		else:
			ctype, name = arg.split(' ')

		# Transfer the pointer stars to the type.
		if '*' in name:
			count = name.rindex('*') - name.index('*') + 1
			name = name[name.rindex('*') + 1:]
			ctype = ctype + ' ' + ('*'*count)

		if not ctype in types: types.append(ctype)

		nargs.append({ "name": name, "type": ctype })

	if len(nargs) > max_len: max_len = len(nargs)
	total_count = total_count + 1
	total.append({"funcname": funcname, "number": number, "args": nargs})

formatted.write(json.dumps(total, indent=4))
print "Parsed", total_count, "syscalls. The longest is", max_len, "arguments"
print "All types:"
for t in types: print t
formatted.close()