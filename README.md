# KeePass to John Converter 🔑🔓
Convert your KeePass databases (kdbx) to John the Ripper's format effortlessly using this conversion tool. The tool is available in both Python and Perl implementations.

[![License: CC0-1.0](https://img.shields.io/badge/License-CC0--1.0-green.svg)](http://creativecommons.org/publicdomain/zero/1.0/)
[![Python 3](https://img.shields.io/badge/Python-3-blue.svg)](https://www.python.org)
[![Perl 5](https://img.shields.io/badge/Perl-5-blue.svg)](https://www.perl.org)

## Features
- Converts KeePass databases to John the Ripper's format for password analysis
- Handles both 1.x and 2.x KeePass database formats
- Provides implementations in Python and Perl
- Generates format-compatible output files ready for John the Ripper

## Getting Started
Clone this repository:

`git clone https://github.com/ivanmrsulja/keepass2john.git`

### Python Implementation:
Run the Python script:

`python keepass2john.py your_database.kdbx > output_john.txt`

### Perl Implementation:
Run the Perl script:

`perl keepass2john.pl your_database.kdbx > output_john.txt`

#### Replace `your_database.kdbx` with your KeePass database filename and `output_john.txt` with the desired output filename

### Use the generated output file with John the Ripper or Hashcat:

`john --format=keepass output_john.txt`

`hashcat -m 13400 -a 0 output_john.txt rockyou.txt --force --show`
