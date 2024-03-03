using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

public class Server
{

    public static TcpListener tcpListener;
    public static TcpClient client = new TcpClient();
    public static NetworkStream stream;

    static ConcurrentQueue<byte[]> incomingDataQueue =  new ConcurrentQueue<byte[]>();
    static ConcurrentQueue<byte[]> outgoingDataQueue = new ConcurrentQueue<byte[]>();

    public static bool exit = false;

    static AsymmetricCipherKeyPair keyPair;
    static byte[] sharedSecret;
    static byte[] sessionKey;

    public static void Main(string[] args)
    {
        // Perform startup tasks
        // ...
        Console.WriteLine("Server started");

        // Setup TCP listener
        tcpListener = new TcpListener(3333);
        tcpListener.Start();

        // Accept incoming connection
        TcpClient tcpClient = tcpListener.AcceptTcpClient();
        client = tcpClient;
        stream = client.GetStream();

        // Start a new thread to handle the client
        Thread t = new Thread(HandleData);   
        t.Start();



        // =====================
        // === Crypto set up ===

        // Generate key pair
        keyPair = DHKE_05.DHKE_GenerateKeyPair();

        while (incomingDataQueue.Count != 1)
        {
            Thread.Sleep(10);
        }

        // Get public key from queue
        incomingDataQueue.TryDequeue(out byte[]? publicKey);

        // Verify
        if (publicKey != null && publicKey.Length == 32)
        {
            Console.WriteLine("Received public key: {0}", BitConverter.ToString(publicKey));
        }

        // Convert own public key to byte array with length prefix
        byte[] ownPublicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
        byte[] buffer = new byte[2 + ownPublicKey.Length];
        byte[] length = BitConverter.GetBytes((ushort)ownPublicKey.Length);

        Buffer.BlockCopy(ownPublicKey, 0, buffer, 2, ownPublicKey.Length);
        Buffer.BlockCopy(length, 0, buffer, 0, 2);

        Console.WriteLine("Own public key: {0}", BitConverter.ToString(ownPublicKey));
        Console.WriteLine("");

        // Send public key to client
        outgoingDataQueue.Enqueue(buffer);

        // Compute shared secret
        sharedSecret = DHKE_05.DHKE_ComputeSharedSecret(keyPair, new X25519PublicKeyParameters(publicKey, 0));

        // Wait for the client to send encrypted session key and iv
        while (incomingDataQueue.Count != 2)
        {
            Thread.Sleep(10);
        }

        // Get encrypted session key and iv from queue
        incomingDataQueue.TryDequeue(out byte[]? encryptedSessionKey);
        incomingDataQueue.TryDequeue(out byte[]? initialVector);

        // Sanity check
        if (encryptedSessionKey == null || initialVector == null)
        {
            Console.WriteLine("Error: Encrypted session key or initial vector is null");
            return;
        }

        // Decrypt the session key and remove padding from AES-CBC
        byte[] sessionKeyWithPadding = AES_CBC.AES_CBC_Decrypt(sharedSecret, initialVector, encryptedSessionKey);
        sessionKey = sessionKeyWithPadding.Take(sharedSecret.Length).ToArray();
        
        Console.WriteLine("Shared secret: " + BitConverter.ToString(sharedSecret));
        Console.WriteLine("Encrypted session key: " + BitConverter.ToString(encryptedSessionKey));
        Console.WriteLine("Session key: " + BitConverter.ToString(sessionKey));

        // === Crypto set up END ===
        // =========================
        
        Console.WriteLine("");
        Console.WriteLine("Ready to receive data");
        Console.WriteLine("");

        // Enter command loop
        while (true)
        {
            // Check if the user has entered a command
            if (Console.KeyAvailable) {
                string command = Console.ReadLine();
                if (command == "exit")
                {
                    // Set running to false to exit the loops
                    exit = true;

                    // Join clients thread and exit    
                    t.Join();

                    Console.WriteLine("Exiting...");
                    break;
                }
                if (command == "dump")
                {
                    while (incomingDataQueue.Count != 0)
                    {
                        // Get data from the queue
                        incomingDataQueue.TryDequeue(out byte[]? data);

                        // Sanity check
                        if (data == null)
                            continue;

                        Console.WriteLine(Encoding.UTF8.GetString(data));
                    }
                }
                if (command == "decryptMessages") {

                    // Check if there is an even number of messages
                    if (incomingDataQueue.Count % 3 != 0) {
                        Console.WriteLine("");
                        Console.WriteLine("Error: Incomplete message");
                        continue;
                    }

                    while (incomingDataQueue.Count != 0)
                    {
                        // Get data from the queue
                        incomingDataQueue.TryDequeue(out byte[]? data);
                        incomingDataQueue.TryDequeue(out byte[]? iv);
                        incomingDataQueue.TryDequeue(out byte[]? auth_tag);

                        // Sanity check
                        if (data == null || iv == null || auth_tag == null)
                            continue;

                        AES_02 aes = new AES_02();

                        // Decrypt the message
                        byte[] decryptedData = aes.AES_GCM_Decrypt(data, sessionKey, iv, auth_tag);

                        Console.WriteLine("");
                        Console.WriteLine("Received message from client:");
                        Console.WriteLine(Encoding.UTF8.GetString(decryptedData) + "\n");
                    }
                }
            }
        }
    }

    public async static void HandleData()
    {
        while (!exit) {
            // Check if the client has data available
            if (client.Available > 0) {
                // Read data length
                byte[] length = new byte[2];
                await stream.ReadExactlyAsync(length, 0, 2);

                // To ushort
                ushort dataLength = BitConverter.ToUInt16(length, 0);

                // Read data
                byte[] buffer = new byte[dataLength];
                await stream.ReadExactlyAsync(buffer, 0, dataLength);
                
                // Put in queue
                incomingDataQueue.Enqueue(buffer);
            }
                
            // Send data to the client
            while (outgoingDataQueue.Count != 0) {

                // Get data from the queue
                outgoingDataQueue.TryDequeue(out byte[]? outgoingData);

                // Sanity check
                if (outgoingData == null)
                    break;

                // Send data to the client
                stream.Write(outgoingData, 0, outgoingData.Length);
            }
                   
        }
    }
}
