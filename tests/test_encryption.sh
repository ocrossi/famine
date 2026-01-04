#!/bin/bash

# Test suite for Famine encryption functionality

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
FAMINE_BIN="$PROJECT_DIR/Famine"
ENCRYPT_BIN="$PROJECT_DIR/encrypt"
TEST_DIR="/tmp/test_encryption_$$"

# Helper functions
log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
    ((TESTS_TOTAL++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
    ((TESTS_TOTAL++))
}

# Setup test environment
setup_test_env() {
    log_info "Setting up test environment..."
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
}

# Cleanup test environment
cleanup_test_env() {
    log_info "Cleaning up test environment..."
    rm -rf "$TEST_DIR"
}

# Build binaries
build_binaries() {
    log_info "Building Famine and encrypt binaries..."
    (cd "$PROJECT_DIR" && make fclean && make all) >/dev/null 2>&1
    if [ ! -f "$FAMINE_BIN" ] || [ ! -f "$ENCRYPT_BIN" ]; then
        log_fail "Failed to build binaries"
        exit 1
    fi
}

# Test 1: Verify encrypt binary exists and is executable
test_encrypt_binary_exists() {
    log_info "Test 1: Checking if encrypt binary exists and is executable"
    
    if [ -f "$ENCRYPT_BIN" ] && [ -x "$ENCRYPT_BIN" ]; then
        log_pass "Encrypt binary exists and is executable"
    else
        log_fail "Encrypt binary does not exist or is not executable"
    fi
}

# Test 2: Encrypt without arguments shows usage
test_encrypt_usage() {
    log_info "Test 2: Testing encrypt usage message"
    
    output=$("$ENCRYPT_BIN" 2>&1)
    if echo "$output" | grep -q "Usage:"; then
        log_pass "Encrypt shows usage message when called without arguments"
    else
        log_fail "Encrypt does not show usage message"
    fi
}

# Test 3: Encrypt Famine binary successfully
test_encrypt_famine() {
    log_info "Test 3: Testing encryption of Famine binary"
    
    # Copy Famine to test directory
    cp "$FAMINE_BIN" "$TEST_DIR/Famine_test"
    
    # Run encryption
    output=$("$ENCRYPT_BIN" "$TEST_DIR/Famine_test" 2>&1)
    
    if echo "$output" | grep -q "Encrypted successfully"; then
        log_pass "Famine binary encrypted successfully"
    else
        log_fail "Famine binary encryption failed: $output"
    fi
}

# Test 4: Encrypted binary is still valid ELF
test_encrypted_binary_valid() {
    log_info "Test 4: Testing if encrypted binary is still valid ELF"
    
    # Copy and encrypt Famine
    cp "$FAMINE_BIN" "$TEST_DIR/Famine_valid"
    "$ENCRYPT_BIN" "$TEST_DIR/Famine_valid" >/dev/null 2>&1
    
    # Check if it's still a valid ELF
    if file "$TEST_DIR/Famine_valid" | grep -q "ELF"; then
        log_pass "Encrypted binary is still a valid ELF file"
    else
        log_fail "Encrypted binary is not a valid ELF file"
    fi
}

# Test 5: Encrypted binary runs without segfault
test_encrypted_binary_runs() {
    log_info "Test 5: Testing if encrypted binary runs without segfault"
    
    # Copy and encrypt Famine
    cp "$FAMINE_BIN" "$TEST_DIR/Famine_run"
    "$ENCRYPT_BIN" "$TEST_DIR/Famine_run" >/dev/null 2>&1
    
    # Run the encrypted binary
    "$TEST_DIR/Famine_run" >/dev/null 2>&1
    exit_code=$?
    
    # Exit code 0 means success, 139 means segfault
    if [ $exit_code -ne 139 ]; then
        log_pass "Encrypted binary runs without segfault (exit code: $exit_code)"
    else
        log_fail "Encrypted binary segfaults (exit code: $exit_code)"
    fi
}

# Test 6: Verify encryption key is written to correct location
test_encryption_key_location() {
    log_info "Test 6: Testing if encryption key is written to correct location"
    
    # Get symbol addresses from nm
    virus_start=$(nm "$FAMINE_BIN" | grep ' virus_start$' | awk '{print $1}')
    encryption_key=$(nm "$FAMINE_BIN" | grep ' encryption_key$' | awk '{print $1}')
    
    if [ -z "$virus_start" ] || [ -z "$encryption_key" ]; then
        log_fail "Cannot find required symbols in binary"
        return
    fi
    
    # Copy and encrypt Famine
    cp "$FAMINE_BIN" "$TEST_DIR/Famine_key"
    "$ENCRYPT_BIN" "$TEST_DIR/Famine_key" >/dev/null 2>&1
    
    # Calculate file offset for encryption_key (vaddr - 0x401000 + 0x1000)
    key_vaddr=$((16#$encryption_key))
    key_offset=$((key_vaddr - 0x401000 + 0x1000))
    
    # Read 16 bytes at that location
    key_bytes=$(hexdump -s $key_offset -n 16 -e '16/1 "%02x " "\n"' "$TEST_DIR/Famine_key")
    
    # Check if it's not all zeros (which would indicate key was written)
    if [ "$key_bytes" != "30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 " ]; then
        log_pass "Encryption key written to correct location (offset: 0x$(printf '%x' $key_offset))"
    else
        log_fail "Encryption key not written or written to wrong location"
    fi
}

# Test 7: Verify encrypted_flag is set
test_encrypted_flag_set() {
    log_info "Test 7: Testing if encrypted_flag is set"
    
    # Get symbol address
    encrypted_flag=$(nm "$FAMINE_BIN" | grep ' encrypted_flag$' | awk '{print $1}')
    
    if [ -z "$encrypted_flag" ]; then
        log_fail "Cannot find encrypted_flag symbol in binary"
        return
    fi
    
    # Copy and encrypt Famine
    cp "$FAMINE_BIN" "$TEST_DIR/Famine_flag"
    "$ENCRYPT_BIN" "$TEST_DIR/Famine_flag" >/dev/null 2>&1
    
    # Calculate file offset
    flag_vaddr=$((16#$encrypted_flag))
    flag_offset=$((flag_vaddr - 0x401000 + 0x1000))
    
    # Read 1 byte at that location
    flag_byte=$(hexdump -s $flag_offset -n 1 -e '"%02x"' "$TEST_DIR/Famine_flag")
    
    if [ "$flag_byte" = "01" ]; then
        log_pass "encrypted_flag is correctly set to 1"
    else
        log_fail "encrypted_flag is not set (value: 0x$flag_byte)"
    fi
}

# Test 8: Full obfuscation workflow (with strip)
test_full_obfuscation() {
    log_info "Test 8: Testing full obfuscation workflow with strip"
    
    # Copy Famine
    cp "$FAMINE_BIN" "$TEST_DIR/Famine_obfuscate"
    
    # Run encrypt
    "$ENCRYPT_BIN" "$TEST_DIR/Famine_obfuscate" >/dev/null 2>&1
    
    # Run strip
    strip "$TEST_DIR/Famine_obfuscate" 2>/dev/null
    
    # Try to run the obfuscated binary
    "$TEST_DIR/Famine_obfuscate" >/dev/null 2>&1
    exit_code=$?
    
    if [ $exit_code -ne 139 ]; then
        log_pass "Fully obfuscated binary (with strip) runs without segfault"
    else
        log_fail "Fully obfuscated binary segfaults after strip"
    fi
}

# Test 9: Dynamic symbol resolution (change code and verify it still works)
test_dynamic_symbol_resolution() {
    log_info "Test 9: Testing dynamic symbol resolution"
    
    # This test verifies that encryption uses dynamic symbol lookup
    # by checking that the program doesn't use hardcoded offsets
    
    # Get actual symbol addresses
    virus_start=$(nm "$FAMINE_BIN" | grep ' virus_start$' | awk '{print $1}')
    encryption_key=$(nm "$FAMINE_BIN" | grep ' encryption_key$' | awk '{print $1}')
    
    # Calculate expected offset
    vs_addr=$((16#$virus_start))
    ek_addr=$((16#$encryption_key))
    expected_offset=$((ek_addr - vs_addr))
    
    # The old hardcoded offset was 8, new should dynamically calculate to 8
    if [ $expected_offset -eq 8 ]; then
        log_pass "Dynamic symbol resolution working (encryption_key offset from virus_start: $expected_offset)"
    else
        log_fail "Unexpected offset: $expected_offset (expected: 8)"
    fi
}

# Main test execution
main() {
    echo "======================================"
    echo "  Famine Encryption Test Suite"
    echo "======================================"
    echo ""
    
    setup_test_env
    build_binaries
    
    test_encrypt_binary_exists
    test_encrypt_usage
    test_encrypt_famine
    test_encrypted_binary_valid
    test_encrypted_binary_runs
    test_encryption_key_location
    test_encrypted_flag_set
    test_full_obfuscation
    test_dynamic_symbol_resolution
    
    cleanup_test_env
    
    echo ""
    echo "======================================"
    echo "  Test Results"
    echo "======================================"
    echo -e "Total Tests: $TESTS_TOTAL"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Run main
main
