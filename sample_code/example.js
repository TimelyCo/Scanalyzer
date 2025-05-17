/**
 * Example JavaScript code with various issues for testing the analyzer
 */

// Security issue: Unsafe eval
function calculate(expression) {
    // Security risk: Code injection
    return eval(expression);
}

// Performance issue: Inefficient array building
function inefficientListBuilder(n) {
    let result = [];
    for (let i = 0; i < n; i++) {
        result = result.concat([i]); // Should use push instead
    }
    return result;
}

// Security issue: Command injection risk
const { exec } = require("child_process");

function runCommand(command) {
    // Security risk: Command injection
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error.message}`);
        } else {
            console.log(`Output: ${stdout}`);
        }
    });
}

// Performance issue: Expensive copying
function processData(dataList) {
    let results = [];
    for (let data of dataList) {
        let copy = JSON.parse(JSON.stringify(data)); // Inefficient deep copy
        results.push(copy);
    }
    return results;
}

// Syntax error example (commented out)
// function brokenSyntax( {
//     console.log("Missing closing parenthesis");

// Style issue: Unused variable
function unusedVariable() {
    let x = 10; // Unused
    let y = 20;
    return y;
}

// Logical issue: Unreachable code
function unreachableCode() {
    return "Done";
    console.log("This will never be shown"); // Unreachable
}

// Nested loop performance issue
function nestedComprehension() {
    let matrix = [[1, 2], [3, 4]];
    let flattened = matrix.flat(); // Okay

    let nested = [];
    for (let i = 0; i < 100; i++) {
        let row = [];
        for (let j = 0; j < 100; j++) {
            row.push(i * j); // Performance concern
        }
        nested.push(row);
    }
    return nested;
}

// Main function with many issues
function main() {
    const readline = require("readline").createInterface({
        input: process.stdin,
        output: process.stdout
    });

    readline.question("Enter a mathematical expression: ", (expr) => {
        const result = calculate(expr); // Unsafe
        console.log(`Result: ${result}`);

        const largeList = inefficientListBuilder(1000);
        console.log(`List size: ${largeList.length}`);

        readline.question("Enter a shell command: ", (cmd) => {
            runCommand(cmd); // Unsafe

            const data = [{ a: 1, b: 2 }, { a: 3, b: 4 }];
            const processed = processData(data);
            console.log("Processed data:", processed);

            unreachableCode();

            readline.close();
        });
    });
}

main();
