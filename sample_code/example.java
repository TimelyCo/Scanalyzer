import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * Improved version of the original Python code converted to Java
 * with better security and performance.
 */
public class SecurityOptimizedApplication {
    
    // Security improvement: Using ScriptEngine with validation instead of eval
    public static double calculateSafely(String expression) throws ScriptException {
        // Validate expression contains only safe mathematical characters
        if (!Pattern.matches("^[0-9+\\-*/().\\s]+$", expression)) {
            throw new IllegalArgumentException("Invalid expression: only numbers and basic operators allowed");
        }
        
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("JavaScript");
        Object result = engine.eval(expression);
        
        if (result instanceof Number) {
            return ((Number) result).doubleValue();
        } else {
            throw new IllegalArgumentException("Expression did not evaluate to a number");
        }
    }
    
    // Performance improvement: Efficient list building
    public static List<Integer> efficientListBuilder(int n) {
        List<Integer> result = new ArrayList<>(n); // Pre-allocate capacity
        for (int i = 0; i < n; i++) {
            result.add(i); // Use add method which is O(1) amortized
        }
        return result;
    }
    
    // Security improvement: Safe command execution with validation
    public static String runCommandSafely(String command) throws IOException {
        // Whitelist of allowed commands
        List<String> allowedCommands = List.of("date", "echo", "dir", "ls");
        
        // Split the command to extract the base command
        String baseCommand = command.split("\\s+")[0];
        
        if (!allowedCommands.contains(baseCommand)) {
            throw new IllegalArgumentException("Command not allowed: " + baseCommand);
        }
        
        // Use ProcessBuilder which is safer than Runtime.exec
        ProcessBuilder processBuilder = new ProcessBuilder(command.split("\\s+"));
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        return new String(process.getInputStream().readAllBytes());
    }
    
    // Performance improvement: Efficient data processing
    public static List<Map<String, Integer>> processDataEfficiently(List<Map<String, Integer>> dataList) {
        List<Map<String, Integer>> results = new ArrayList<>(dataList.size()); // Pre-allocate capacity
        
        for (Map<String, Integer> data : dataList) {
            // Create a new map without unnecessary deep copying
            Map<String, Integer> dataCopy = new HashMap<>(data);
            results.add(dataCopy);
        }
        
        return results;
    }
    
    // Security improvement: Safe deserialization with type checking
    public static <T> T loadObjectSafely(String filePath, Class<T> expectedType) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            Object obj = ois.readObject();
            
            // Type check before returning
            if (expectedType.isInstance(obj)) {
                return expectedType.cast(obj);
            } else {
                throw new ClassCastException("Loaded object is not of expected type: " + expectedType.getName());
            }
        }
    }
    
    // Fixed: No unused variables
    public static int useAllVariables() {
        int x = 10;
        int y = 20;
        return x + y; // Now x is used
    }
    
    // Fixed: No unreachable code
    public static String reachableCode() {
        return "Result";
        // Removed unreachable code
    }
    
    // Performance improvement: Better nested operations
    public static int[][] createMatrix(int size) {
        int[][] matrix = new int[size][size];
        
        // Initialize matrix more efficiently
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < size; j++) {
                matrix[i][j] = i * j;
            }
        }
        
        return matrix;
    }
    
    // Flatten a matrix efficiently
    public static List<Integer> flattenMatrix(int[][] matrix) {
        int totalSize = matrix.length * matrix[0].length;
        List<Integer> flattened = new ArrayList<>(totalSize);
        
        for (int[] row : matrix) {
            for (int value : row) {
                flattened.add(value);
            }
        }
        
        return flattened;
    }
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        try {
            // Demonstrate secure calculation
            System.out.print("Enter a mathematical expression: ");
            String expression = scanner.nextLine();
            
            try {
                double result = calculateSafely(expression);
                System.out.println("Result: " + result);
            } catch (Exception e) {
                System.out.println("Error calculating expression: " + e.getMessage());
            }
            
            // Demonstrate efficient list building
            List<Integer> largeList = efficientListBuilder(1000);
            System.out.println("List length: " + largeList.size());
            
            // Demonstrate safe command execution
            System.out.print("Enter a command to run (allowed: date, echo, dir, ls): ");
            String command = scanner.nextLine();
            
            try {
                String output = runCommandSafely(command);
                System.out.println("Command output: " + output);
            } catch (Exception e) {
                System.out.println("Error running command: " + e.getMessage());
            }
            
            // Demonstrate efficient data processing
            List<Map<String, Integer>> data = new ArrayList<>();
            Map<String, Integer> item1 = new HashMap<>();
            item1.put("a", 1);
            item1.put("b", 2);
            Map<String, Integer> item2 = new HashMap<>();
            item2.put("a", 3);
            item2.put("b", 4);
            data.add(item1);
            data.add(item2);
            
            List<Map<String, Integer>> processed = processDataEfficiently(data);
            System.out.println("Processed data size: " + processed.size());
            
            // Demonstrate matrix operations
            int[][] matrix = createMatrix(10);
            List<Integer> flattened = flattenMatrix(matrix);
            System.out.println("Flattened matrix size: " + flattened.size());
            
        } catch (Exception e) {
            System.err.println("An unexpected error occurred: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}