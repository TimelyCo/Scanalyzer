"""
Example Python code with various issues for testing the analyzer
"""

import os
import subprocess
import pickle

# Security issue: Unsafe use of eval
def calculate(expression):
    """Calculate the result of an expression using eval (unsafe)"""
    return eval(expression)  # Security risk: Code injection

# Performance issue: Inefficient list appending
def inefficient_list_builder(n):
    """Build a list inefficiently"""
    result = []
    for i in range(n):
        result = result + [i]  # Performance issue: should use append
    return result

# Security issue: Command injection risk
def run_command(command):
    """Run a shell command (unsafe)"""
    return os.system(command)  # Security risk: Command injection

# Performance issue: Expensive operation in loop
def process_data(data_list):
    """Process data inefficiently"""
    results = []
    for data in data_list:
        # Performance issue: Expensive copy in loop
        data_copy = data.copy()  
        results.append(data_copy)
    return results

# Syntax error example (commented out)
# def function_with_syntax_error()
#     print("This has a syntax error")

# Security issue: Unsafe deserialization
def load_object(file_path):
    """Load a pickled object (unsafe)"""
    with open(file_path, 'rb') as f:
        return pickle.load(f)  # Security risk: Deserialization vulnerability

# Style issue: Unused variable
def unused_variables():
    """Function with unused variables"""
    x = 10  # Unused variable
    y = 20
    return y

# Logical issue: Unreachable code
def unreachable_code():
    """Function with unreachable code"""
    return "Result"
    print("This will never be executed")  # Unreachable code

# Nested list comprehension (potential performance issue)
def nested_comprehension():
    """Function with nested list comprehension"""
    matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
    flattened = [x for row in matrix for x in row]  # Not an issue
    
    # Performance issue: Nested list comprehension
    nested = [
        [x * y for x in range(10)] 
        for y in range(10)
    ]
    return nested

# Main function with multiple issues
def main():
    """Main function with various issues"""
    # Security issue: Unsafe input
    user_input = input("Enter a mathematical expression: ")
    result = calculate(user_input)
    print(f"Result: {result}")
    
    # Performance issue
    large_list = inefficient_list_builder(1000)
    print(f"List length: {len(large_list)}")
    
    # Another security issue
    command = input("Enter a command to run: ")
    run_command(command)
    
    # More issues
    data = [{'a': 1, 'b': 2}, {'a': 3, 'b': 4}]
    processed = process_data(data)
    
    # Unreachable due to previous security issues likely causing problems
    unreachable_code()

if __name__ == "__main__":
    main()