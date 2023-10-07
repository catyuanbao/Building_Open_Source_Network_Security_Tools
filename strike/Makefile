# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g

# Libraries and library paths
LIBS = -lpcap
LDFLAGS = -L/path/to/libpcap

# Source files
SRCS = strike.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
EXEC = strike

# Rules
all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXEC) $(OBJS)

