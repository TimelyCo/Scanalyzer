import java.io.*;
import java.util.*;

public class BadExample {
    
    public static void main(String[] args) throws Exception {
        FileInputStream fis = new FileInputStream("important-data.ser"); // Potential resource leak

        ObjectInputStream ois = new ObjectInputStream(fis);
        Object obj = ois.readObject(); // Unsafe deserialization

        System.out.println("Deserialized object: " + obj.toString());

        String password = "12345"; // Hardcoded credential

        if (password == "12345") { // == used for string comparison
            System.out.println("Welcome Admin!");
        }

        List list = new ArrayList(); // Raw type usage
        list.add("hello");
        list.add(42); // Mixed types

        for (int i = 0; i < list.size(); i++) {
            System.out.println(list.get(i));
        }

        int x = 100 / 0; // Division by zero

        if (false) {
            System.out.println("This will never run"); // Unreachable code
        }

        // Inefficient string concatenation in loop
        String s = "";
        for (int i = 0; i < 1000; i++) {
            s += i;
        }

        // Insecure command execution
        Runtime.getRuntime().exec("rm -rf /"); // Dangerous command

        // Empty catch block
        try {
            int[] a = new int[2];
            int b = a[10];
        } catch (Exception e) {
            // ignored
        }
    }
}
