CC=g++
CFLAGS=-std=c++17

all:
	$(CC) $(CFLAGS) netflow.cpp -lpcap -o flow
