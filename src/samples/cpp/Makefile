CXX = g++
CXXFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto

TARGET = cryptoSamples
SRC = cryptoSamples.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

install-deps:
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev

# NOTE for Windows users:
# Ensure g++ is installed and available in your PATH.
# You can install MinGW (https://www.mingw-w64.org/) or use WSL (Windows Subsystem for Linux).
# OpenSSL development libraries must also be installed and available to the compiler.

# NOTE for WSL users:
# If you see "g++: No such file or directory", install g++ and OpenSSL dev libraries:
#   sudo apt update
#   sudo apt install build-essential libssl-dev