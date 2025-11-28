# Compiler and flags
AS      = nasm
ASFLAGS = -f elf64 -I includes -I sources

# Directories
SRC_DIR  = sources
OBJ_DIR  = objects
BIN_DIR  = .
BIN_NAME = Famine

# Source files
SRC_S    = sources/main.s

# Object files (replace .s/.c with .o and change path)
OBJ_S    = $(patsubst $(SRC_DIR)/%.s,$(OBJ_DIR)/%.o,$(SRC_S))
OBJS     = $(OBJ_S)

# Target executable
TARGET   = $(BIN_DIR)/$(BIN_NAME)

# Default target
all: $(TARGET)

# Create objects directory if it doesn't exist

$(OBJ_DIR):
	$(shell mkdir -p $(OBJ_DIR))

# Link object files into executable
$(TARGET): $(OBJS)
	ld $^ -o $@

# Compile .s files to .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(TARGET)

re: fclean all

.PHONY: clean fclean re
