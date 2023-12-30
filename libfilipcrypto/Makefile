CFLAGS   := -Iinclude -pipe -pedantic -g -Wall -Wextra -O3 -ffast-math -Wno-deprecated -Wno-deprecated-declarations

SRC_DIR  := src
BIN_DIR  := bin
OBJ_DIR  := $(BIN_DIR)/obj
EXPORT_DIR := export

LIB      := $(EXPORT_DIR)/libfilipcrypto.a
SRC      := $(wildcard $(SRC_DIR)/*.c)
OBJ      := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))


.PHONY: all

all: $(LIB)

$(LIB): $(OBJ) | $(EXPORT_DIR)
	$(AR) rcs $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR) $(EXPORT_DIR):
	mkdir -p $@

.PHONY: clean
clean:
	rm -r bin/*
