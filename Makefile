CC=g++
CPFLAGS=-g
LDFLAGS= -lpcap

SRC= wiretap.cpp wt_setup.cpp
OBJ=$(SRC:.cpp=.o)
BIN=wiretap

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.cpp
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
