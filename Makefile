# Compiler and flags
AS      = nasm
ASFLAGS = -f elf64 -I includes -I sources

# Directories
SRC_DIR  = sources
OBJ_DIR  = objects
BIN_DIR  = .
BIN_NAME = Famine
TOOLS_DIR = tools
ENCRYPT_TOOL = $(TOOLS_DIR)/encrypt_famine

VERBOSE_FLAG :=
ifeq ($(filter -v,$(MAKECMDGOALS)),-v)
VERBOSE_FLAG := -v
endif
ifeq ($(VERBOSE),1)
VERBOSE_FLAG := -v
endif
ifneq (,$(findstring -v,$(MAKEFLAGS)))
VERBOSE_FLAG := -v
endif
ifeq ($(filter verbose,$(MAKECMDGOALS)),verbose)
VERBOSE_FLAG := -v
endif

INSPECT_MODE :=
ifneq (,$(filter inspect,$(MAKECMDGOALS)))
INSPECT_MODE := 1
VERBOSE_FLAG := -v
endif
ifeq ($(INSPECT),1)
INSPECT_MODE := 1
VERBOSE_FLAG := -v
endif

# Source files
SRC_S    = sources/main.s

# Object files (replace .s/.c with .o and change path)
OBJ_S    = $(patsubst $(SRC_DIR)/%.s,$(OBJ_DIR)/%.o,$(SRC_S))
OBJS     = $(OBJ_S)

# Target executable
TARGET   = $(BIN_DIR)/$(BIN_NAME)

# Default target
all: $(TARGET) encrypt

# Create objects directory if it doesn't exist

$(OBJ_DIR):
	$(shell mkdir -p $(OBJ_DIR))

# Link object files into executable
$(TARGET): $(OBJS)
	ld $^ -o $@

# Encryption tool
encrypt: $(TARGET)
	python3 ./tools/encrypt_famine.py

# Compile .s files to .o
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s | $(OBJ_DIR)
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -rf $(OBJ_DIR)
	rm -f $(ENCRYPT_TOOL) $(ENCRYPT_TOOL).o

fclean: clean
	rm -f $(TARGET)

re: fclean all

test: all
	INSPECT=$(INSPECT_MODE) VERBOSE=$(if $(INSPECT_MODE),1,$(VERBOSE)) ./tests/test_famine.sh $(VERBOSE_FLAG)

# Dummy target so `make test -v` works without error
-v:
verbose:
inspect:

.PHONY: clean fclean re test -v verbose inspect encrypt
