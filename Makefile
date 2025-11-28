# Compiler and flags
AS      = nasm
ASFLAGS = -f elf64 -I includes

# Directories
SRC_DIR  = sources
OBJ_DIR  = objects
BIN_DIR  = .

# Source files and their targets
FAMINE_SRC = $(SRC_DIR)/hello.s
FAMINE_OBJ = $(OBJ_DIR)/hello.o
FAMINE_BIN = $(BIN_DIR)/Famine

LIST_FILES_SRC = $(SRC_DIR)/list_files.s
LIST_FILES_OBJ = $(OBJ_DIR)/list_files.o
LIST_FILES_BIN = $(BIN_DIR)/list_files

# Default target - build both executables
all: $(FAMINE_BIN) $(LIST_FILES_BIN)

# Create objects directory if it doesn't exist
$(OBJ_DIR):
	$(shell mkdir -p $(OBJ_DIR))

# Link Famine executable
$(FAMINE_BIN): $(FAMINE_OBJ)
	ld $^ -o $@

# Link list_files executable
$(LIST_FILES_BIN): $(LIST_FILES_OBJ)
	ld $^ -o $@

# Compile .s files to .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(FAMINE_BIN) $(LIST_FILES_BIN)

re: fclean all

.PHONY: clean fclean re all
