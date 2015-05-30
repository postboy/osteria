#!/bin/sh
#компиляция без запуска, в тестовом режиме

#компилировать со всеми предупреждениями, с подключением библиотеки GTK+, в объектный файл ost
gcc -Wall `pkg-config --cflags gtk+-3.0` src/main.c src/crypto.c src/stuff.c src/tweetnacl.c `pkg-config --libs gtk+-3.0` -o ost
