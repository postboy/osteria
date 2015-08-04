#!/bin/sh
#compilation & launch for testing

#compile with all warnings, using libgtk, in object file "ost"
gcc -Wall `pkg-config --cflags gtk+-3.0` src/main.c src/crypto.c src/stuff.c src/tweetnacl.c `pkg-config --libs gtk+-3.0` -o ost
#and launch
./ost
