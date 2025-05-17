/**
 * Example C++ code with various issues for testing the analyzer
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <map>
#include <algorithm>
#include <fstream>
#include <cstring>

// Security issue: Unsafe use of system
std::string execute_command(const std::string& command) {
    /**
     * Execute a system command (unsafe)
     */
    system(command.c_str());  // Security risk: Command injection
    return "Command executed";
}

// Security issue: Buffer overflow risk
void copy_string(char* dest, const char* src) {
    /**
     * Copy string without bounds checking (unsafe)
     */
    strcpy(dest, src);  // Security risk: Buffer overflow
}

// Performance issue: Inefficient vector appending
std::vector<int> inefficient_vector_builder(int n) {
    /**
     * Build a vector inefficiently
     */
    std::vector<int> result;
    for (int i = 0; i < n; i++) {
        // Performance issue: should use push_back or reserve capacity first
        std::vector<int> temp = result;
        temp.push_back(i);
        result = temp;
    }
    return result;
}

// Security issue: Memory leak
int* create_array(int size) {
    /**
     * Create an array with memory leak
     */
    int* arr = new int[size];  // Memory allocated but never freed
    for (int i = 0; i < size; i++) {
        arr[i] = i;
    }
    return arr;  // Memory leak: caller responsible for deleting
}

// Performance issue: Expensive operation in loop
void process_data(const std::vector<std::map<std::string, int>>& data_list) {
    /**
     * Process data inefficiently
     */
    std::vector<std::map<std::string, int>> results;
    for (const auto& data : data_list) {
        // Performance issue: Expensive copy in loop
        std::map<std::string, int> data_copy = data;
        
        // Performance issue: Expensive operation in loop
        std::sort(data_copy.begin(), data_copy.end());  // This won't actually compile for map
        
        results.push_back(data_copy);
    }
}

// Syntax error example (commented out)
/*
void function_with_syntax_error() {
    std::cout << "This has a syntax error"  // Missing semicolon
}
*/

// Security issue: Unsafe file handling
std::string read_file(const std::string& filename) {
    /**
     * Read a file without proper checks (unsafe)
     */
    std::ifstream file(filename);  // No existence check
    std::string content;
    std::string line;
    while (std::getline(file, line)) {
        content += line + "\n";
    }
    return content;
}

// Buffer overflow risk
void unsafe_buffer_operation() {
    /**
     * Unsafe buffer operation with gets
     */
    char buffer[10];
    std::cout << "Enter your name: ";
    gets(buffer);  // Security risk: Buffer overflow
    std::cout << "Hello, " << buffer << "!" << std::endl;
}

// Dangerous scanf usage
void format_string_vulnerability() {
    /**
     * Format string vulnerability with scanf
     */
    char buffer[100];
    printf("Enter format string: ");
    scanf("%s", buffer);  // Security risk: Format string vulnerability
    printf(buffer);  // Security risk: Format string vulnerability
}

// Style issue: Unused variable
int unused_variables() {
    /**
     * Function with unused variables
     */
    int x = 10;  // Unused variable
    int y = 20;
    return y;
}

// Logical issue: Unreachable code
std::string unreachable_code() {
    /**
     * Function with unreachable code
     */
    return "Result";
    std::cout << "This will never be executed" << std::endl;  // Unreachable code
}

// Performance issue: Inefficient memory usage
void memory_inefficiency() {
    /**
     * Function with memory inefficiency
     */
    for (int i = 0; i < 1000; i++) {
        // Performance issue: Memory allocation in loop
        int* data = new int[100];
        data[0] = i;
        
        // Memory leak: Never freed
    }
}

// Memory access issue
void out_of_bounds_access() {
    /**
     * Function with out-of-bounds access
     */
    int array[10];
    for (int i = 0; i <= 10; i++) {  // Security risk: Off-by-one error
        array[i] = i;  // Will access array[10] which is out of bounds
    }
}

// Uninitialized variable
int uninitialized_variable() {
    /**
     * Function using uninitialized variable
     */
    int x;  // Uninitialized
    int y = 10;
    return x + y;  // Using uninitialized value
}

// Integer overflow
unsigned int integer_overflow() {
    /**
     * Function with potential integer overflow
     */
    unsigned int max = -1;  // Sets to max value of unsigned int
    return max + 1;  // Will overflow
}

// Main function with multiple issues
int main() {
    /**
     * Main function with various issues
     */
    // Security issue: Unsafe input
    std::string command;
    std::cout << "Enter a command to run: ";
    std::getline(std::cin, command);
    execute_command(command);
    
    // Performance issue
    std::vector<int> large_vec = inefficient_vector_builder(1000);
    std::cout << "Vector size: " << large_vec.size() << std::endl;
    
    // Memory leak
    int* numbers = create_array(100);
    // numbers is never deleted
    
    // More security issues
    char small_buffer[10];
    char* large_input = new char[100];
    std::cout << "Enter your name: ";
    std::cin >> large_input;
    copy_string(small_buffer, large_input);  // Potential buffer overflow
    
    // Clean up large_input to avoid memory leak
    delete[] large_input;
    
    // Potentially dangerous file operation
    std::string file_content = read_file("user_input.txt");  // File may not exist
    
    // Unreachable code due to previous issues likely causing crashes
    unreachable_code();
    
    // Memory leak
    memory_inefficiency();
    
    // Out of bounds access
    out_of_bounds_access();
    
    return 0;
}
