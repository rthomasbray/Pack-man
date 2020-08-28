import sys

stub_path = sys.argv[1]
header_path = sys.argv[2]

f = open(stub_path,"rb")
bl = f.read()
f.close()

# Get first character outside loop so that we don't have a trailing comma
outstr = hex(bl[0])

for b in bl[1:]:
	outstr = outstr + "," + hex(b)


f = open(header_path,"w")
f.write(outstr)
f.close()

# fini