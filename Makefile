# =============================================================
#  Makefile generico per progetti C su Windows (MinGW/GCC)
#  Uso: make
#       make clean
#       make rebuild
# =============================================================

# --- Compilatore e flag ---
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lpsapi -lkernel32 -ladvapi32

# --- File sorgenti e output ---
SRCS    = $(wildcard *.c)
OBJS    = $(SRCS:.c=.o)
TARGET  = process_analyzer.exe

# --- Regola principale ---
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo Compilato: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# --- Pulizia ---
clean:
	del /Q *.o $(TARGET) 2>nul || true

rebuild: clean all

.PHONY: all clean rebuild