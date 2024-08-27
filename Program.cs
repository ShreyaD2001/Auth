using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

class Program
{
    // A dictionary to store user credentials
    private static Dictionary<string, string> users = new Dictionary<string, string>();

    static void Main(string[] args)
    {
        bool exit = false;
        while (!exit)
        {
            Console.WriteLine("\n*** Authentication System ***");
            Console.WriteLine("1. Register");
            Console.WriteLine("2. Login");
            Console.WriteLine("3. Exit");
            Console.Write("Choose an option: ");

            switch (Console.ReadLine())
            {
                case "1":
                    Register();
                    break;
                case "2":
                    Login();
                    break;
                case "3":
                    exit = true;
                    break;
                default:
                    Console.WriteLine("Invalid option! Please try again.");
                    break;
            }
        }
    }

    private static void Register()
    {
        Console.Write("Enter username: ");
        string username = Console.ReadLine();

        if (users.ContainsKey(username))
        {
            Console.WriteLine("Username already exists. Try a different one.");
            return;
        }

        Console.Write("Enter password: ");
        string password = ReadPassword();

        // Hash the password and store it
        string hashedPassword = HashPassword(password);
        users[username] = hashedPassword;

        Console.WriteLine("Registration successful!");
    }

    private static void Login()
    {
        Console.Write("Enter username: ");
        string username = Console.ReadLine();

        if (!users.ContainsKey(username))
        {
            Console.WriteLine("Username does not exist.");
            return;
        }

        Console.Write("Enter password: ");
        string password = ReadPassword();

        // Verify the password
        string storedHashedPassword = users[username];
        if (VerifyPassword(password, storedHashedPassword))
        {
            Console.WriteLine("Login successful!");
        }
        else
        {
            Console.WriteLine("Incorrect password.");
        }
    }

    private static string ReadPassword()
    {
        StringBuilder password = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            else if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                    Console.Write("\b \b"); // Remove the last character from the console
                }
            }
            else
            {
                password.Append(key.KeyChar);
                Console.Write("*"); // Show asterisk instead of the actual password character
            }
        }
        return password.ToString();
    }

    private static string HashPassword(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            StringBuilder builder = new StringBuilder();
            foreach (byte b in bytes)
            {
                builder.Append(b.ToString("x2"));
            }
            return builder.ToString();
        }
    }

    private static bool VerifyPassword(string inputPassword, string storedHashedPassword)
    {
        string inputHashedPassword = HashPassword(inputPassword);
        return inputHashedPassword == storedHashedPassword;
    }
}
