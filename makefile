cc=gcc
cflags=-Wall --pedantic-errors -g --std=c99

main:
	gcc ${cflags} -o ssherp main.c
