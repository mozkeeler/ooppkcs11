CXX=clang++
CXXFLAGS=-I/usr/include/nss3 -I/usr/include/nspr4 -Wall -g -std=c++11
LDFLAGS=-lnss3 -lnspr4

all: libooppkcs11.so ooppkcs11child test dbs
.PHONY: all

dbs:
	certutil -N -d . --empty-password

libooppkcs11.so: ooppkcs11.cpp ooppkcs11util.cpp ooppkcs11util.h
	$(CXX) $(CXXFLAGS) -shared -fPIC ooppkcs11.cpp ooppkcs11util.cpp -o libooppkcs11.so

ooppkcs11child: ooppkcs11child.cpp ooppkcs11util.cpp ooppkcs11util.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -ldl -o ooppkcs11child ooppkcs11child.cpp ooppkcs11util.cpp

test: test.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o test test.cpp

clean:
	rm -f libooppkcs11.so test ooppkcs11child key3.db cert8.db secmod.db
