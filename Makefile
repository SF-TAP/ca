all: ca
.PHONY : all

ca: ca.cpp common.hpp
	$(CXX) -O3 -DDEBUG ./ca.cpp -o ca -lpcap
.PHONY : ca

clean:
	rm -rf ./ca
.PHONY : clean
