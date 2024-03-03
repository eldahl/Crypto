using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

public class Client
{
    static TcpClient client;
    static NetworkStream stream;

    static bool exit = false;

    static byte[] sharedSecret;
    static byte[] sessionKey;

    public static void Main(string[] args)
    {
        // Perform startup tasks
        // ...
        Console.WriteLine("Press any key to start the client");
        Console.ReadKey(true);
        Console.WriteLine("Client started");

        // Connect to the server
        client = new TcpClient("localhost", 3333);
        stream = client.GetStream();

        // =====================
        // === Crypto set up ===

        // Generate key pair
        var keyPair = DHKE_05.DHKE_GenerateKeyPair();

        // Exchange public keys and compute shared secrets
        byte[] publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
        SendData(publicKey);

        // Wait for the server's public key
        Thread.Sleep(1000);

        // Read the server's public key
        byte[] serverPublicKey = ReadData();
        
        // Display the public keys
        Console.WriteLine("Own public key: {0}", BitConverter.ToString(publicKey));
        Console.WriteLine("Received public key: {0}", BitConverter.ToString(serverPublicKey));
        Console.WriteLine("");

        // Compute the shared secret
        sharedSecret = DHKE_05.DHKE_ComputeSharedSecret(keyPair, new X25519PublicKeyParameters(serverPublicKey, 0));
        
        // Generate a session key
        CRNG_01 crng = new CRNG_01();
        sessionKey = crng.CRNG();

        // Encrypt the session key with the shared secret
        byte[] encryptedSessionKey = AES_CBC.AES_CBC_Encrypt(sharedSecret, sessionKey, out byte[] iv);

        // Send the encrypted session key to the server
        SendData(encryptedSessionKey);
        SendData(iv);

        Console.WriteLine("Shared secret: " + BitConverter.ToString(sharedSecret));
        Console.WriteLine("Encrypted session key: " + BitConverter.ToString(encryptedSessionKey));
        Console.WriteLine("Session key: " + BitConverter.ToString(sessionKey));
        Console.WriteLine("");

        // wait for the server to be ready
        Thread.Sleep(1000);

        // === Crypto set up END ===
        // =========================

        var inputTask = ReadInputAsync();

        while (!exit)
        {
            // Get input from the user
            string input = "";
            if (inputTask.IsCompleted)
            {
                input = inputTask.Result;
                inputTask = ReadInputAsync();
            }

            // Handle commands
            if (input == "/exit")
            {
                exit = true;
            }

            if (input != "") {
                // Send data to the server
                byte[] data = Encoding.UTF8.GetBytes(input);
                SendEncryptedMessage(data);
                Console.WriteLine("Sent message: \n" + input + "\n");
            }

            if (client.Available == 0) {
                continue;
            }

            // Read data from the server
            byte[] readData = ReadData();
            string responseData = Encoding.UTF8.GetString(readData);
            Console.WriteLine("Data length: " + readData.Length);
            Console.WriteLine("Received: " + responseData);
        }
        
        // Close the connection
        client.Close();
    }
    static async Task<string> ReadInputAsync()
    {
        StringBuilder inputBuffer = new StringBuilder();
        while (true)
        {
            while (!Console.KeyAvailable)
            {
                await Task.Delay(50);
            }

            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }
            inputBuffer.Append(key.KeyChar);
        }
        return inputBuffer.ToString();
    }

    static void SendData(byte[] data)
    {
        // Send data to the server
        byte[] length = BitConverter.GetBytes((ushort)data.Length);
        byte[] buffer = new byte[data.Length + 2];
        
        Buffer.BlockCopy(length, 0, buffer, 0, 2);
        Buffer.BlockCopy(data, 0, buffer, 2, data.Length);

        stream.Write(buffer, 0, buffer.Length);
    }

    static byte[] ReadData()
    {
        // Read data length
        byte[] length = new byte[2];
        stream.ReadExactly(length, 0, 2);

        // To ushort
        ushort dataLength = BitConverter.ToUInt16(length, 0);

        // Read data
        byte[] buffer = new byte[dataLength];
        stream.ReadExactly(buffer, 0, dataLength);

        return buffer;
    }

    static void SendEncryptedMessage(byte[] data)
    {
        AES_02 aes_gcm = new AES_02();

        // Generate an IV for the encryption
        byte[] iv = RandomNumberGenerator.GetBytes(12);

        // Encrypt the data
        byte[] encryptedData = aes_gcm.AES_GCM_Encrypt(data, sessionKey, iv, out byte[] auth_tag, out int auth_tag_length);

        // Send the encrypted data to the server
        SendData(encryptedData);
        SendData(iv);
        SendData(auth_tag);
    }
}
