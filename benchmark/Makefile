CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wpedantic
CPPFLAGS += $(shell pkg-config --cflags openssl 2>/dev/null)
LDLIBS += -lssl -lcrypto

tlsbench: bench.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

.PHONY: clean
clean:
	rm -f tlsbench
