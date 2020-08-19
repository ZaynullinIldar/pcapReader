all:
	g++ -std=c++17 -c unix_main.cpp reader.cpp
	g++ -o reader unix_main.o reader.o -lpcap -lstdc++fs
clean:
	rm unix_main.o reader.o reader