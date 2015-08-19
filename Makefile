all: ca
.PHONY : all

ca: ca.cpp common.hpp
	$(CXX) -Wall -O3 -DDEBUG ./ca.cpp -o ca -lpcap -lpthread
.PHONY : ca

clean:
	rm -rf ./ca
.PHONY : clean
