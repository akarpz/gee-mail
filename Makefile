LFLAGS = -lcryptopp
CFLAGS = -lcryptopp
CC = g++

all:  geemail

%: %.cc
	g++ -std=c++11 $< -o $@ -lcryptopp -lsqlite3


