# Compiler and flags
CC      = gcc
CFLAGS  = -Wall -Wextra -Werror
AS      = nasm
ASFLAGS = -f elf64 -I includes/

# Directories
SRC_DIR  = sources
OBJ_DIR  = objects
BIN_DIR  = .
BIN_NAME = Famine

# Source files
SRC_ASM  = $(wildcard $(SRC_DIR)/*.asm)
SRC_C    = $(wildcard $(SRC_DIR)/*.c)

# Object files (replace .asm/.c with .o and change path)
OBJ_ASM  = $(patsubst $(SRC_DIR)/%.asm,$(OBJ_DIR)/%.o,$(SRC_ASM))
OBJ_C    = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_C))
OBJS     = $(OBJ_ASM) $(OBJ_C)

# Target executable
TARGET   = $(BIN_DIR)/$(BIN_NAME)

# Default target
all: $(TARGET)

# Create objects directory if it doesn't exist

$(OBJ_DIR):
	$(shell mkdir -p $(OBJ_DIR))

# Link object files into executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -nostdlib -no-pie $^ -o $@

# Compile .c files to .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile .asm files to .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.asm | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(TARGET)

re: fclean all

.PHONY: clean fclean re
