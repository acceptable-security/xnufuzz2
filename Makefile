CC = g++
CFLAGS = -std=c++11 -c -g
LDFLAGS =
NAME = xnufuzz2
EXT = .cpp
SOURCES = $(strip $(wildcard src/*.cpp))
OBJECTS = $(SOURCES:$(EXT)=.o)
EXECUTABLE = $(NAME)
TAR = $(NAME).tar

.PHONY: depend clean

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

$(OBJECTS):
	$(CC) $(CFLAGS) $(subst .o,$(EXT), $@) -o $@

clean:
	rm -f src/*.o $(EXECUTABLE) $(TAR)

tar:
	tar cfv $(TAR) $(SOURCES)