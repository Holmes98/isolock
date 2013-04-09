
isolock: bin bin/isolock

bin:
	mkdir bin

bin/isolock: src/isolock.cpp
	g++ -o $@ $^ -O3

