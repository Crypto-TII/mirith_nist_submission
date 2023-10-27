CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -pedantic -mavx2 -g
DEPS=$(wildcard ../*.h)
OBJ=$(patsubst ../%.c,../%.o,$(wildcard ../*.c))

UNAME_S := $(shell uname -s)
UNAME_P := $(shell uname -p)

ifeq ($(UNAME_S),Linux)
    ASMFLAGS := ${CFLAGS}
endif
ifeq ($(UNAME_S),Darwin)
    ASMFLAGS := ${CFLAGS} -x assembler-with-cpp -Wa,-defsym,old_gas_syntax=1 -Wa,-defsym,no_plt=1
endif
ifneq ($(filter arm%,$(UNAME_P)),)
	OBJ+=$(patsubst ../%.s,../%.o,$(wildcard ../*.s))
endif

all: test_mirith

%.o: %.s
	$(CC) -c $(ASMFLAGS) -o $@ $< 

%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) -o $@ $< 

test_mirith: test_mirith.o $(OBJ)
	$(CC) ${LIBDIR} -o $@ $^ $(CFLAGS) $(LIBS)
	
run: test_mirith
	./test_mirith

.PHONY: clean

clean:
	rm -f *.o *.su
	rm -f ../*.o ../*.su
	rm -f test_mirith

