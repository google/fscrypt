#!/usr/bin/env python

# Exit with 1 if any input is provided. Print the input to stdout, unless an
# argument is specified. In that case, also print the argument.

import sys

input_string = sys.stdin.read()
if input_string != "":
    sys.stdout.write(input_string)
    if len(sys.argv) >= 2:
        print(sys.argv[1])
    sys.exit(1)
