
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.ComponentModel;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Asn1.Cms;

public class Crypto
{
    public static void Main(string[] args)
    {
        AES_CBC.AES_CBC_Print();
    }
}

public class AES_CBC
{
    public static void AES_CBC_Print()
    {
        // Generate a random key and some data
        byte[] key = new CRNG_01().CRNG();
        byte[] data = UTF8Encoding.UTF8.GetBytes("Hello, World!");

        // Encrypt the data
        byte[] encrypted = AES_CBC_Encrypt(key, data, out byte[] iv);
        Console.WriteLine("Encrypted: {0}", BitConverter.ToString(encrypted));

        // Decrypt the data
        byte[] decrypted = AES_CBC_Decrypt(key, iv, encrypted);
        Console.WriteLine("Decrypted: {0}", Encoding.UTF8.GetString(decrypted));
    }

    public static byte[] AES_CBC_Encrypt(byte[] key, byte[] dataToEncrypt, out byte[] iv)
    {
        // Encryption
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.Padding = PaddingMode.PKCS7;

            iv = aes.IV; // Initialization Vector

            using (var encryptor = aes.CreateEncryptor())
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                cryptoStream.FlushFinalBlock();
                return memoryStream.ToArray();
            }
        }
    }

    public static byte[] AES_CBC_Decrypt(byte[] key, byte[] iv, byte[] encryptedData)
    {
        // Decryption
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor())
            using (var memoryStream = new MemoryStream(encryptedData))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            {
                byte[] buffer = new byte[encryptedData.Length];
                cryptoStream.Read(buffer, 0, encryptedData.Length);
                return buffer;
            }
        }
    }
}

/// <summary>
/// PBKDF2-HMAC-SHA512 also called RFC2898
/// </summary>
public class PBKDF2_08
{
    public void PBKDF2_Print()
    {
        // Password to be hashed
        string password = "password";
        Console.WriteLine("Password: {0}", password);

        // Generate a random salt
        byte[] salt = new CRNG_01().CRNG();

        // Derive a key from a password
        byte[] key = PBKDF2_HMAC_SHA512(password, salt, 100000, 256 / 8);
        Console.WriteLine("Key: {0}", BitConverter.ToString(key));
    }

    public byte[] PBKDF2_HMAC_SHA512(string password, byte[] salt, int iterations, int outputBytes)
    {
        return new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512).GetBytes(outputBytes);
    }
}

public class RSA_07
{
    public void RSA_Print()
    {
        // Generate a key pair
        var keyPair = RSA_GenerateKeyPair();

        // Encrypt some data
        byte[] data = UTF8Encoding.UTF8.GetBytes("Hello, World!");
        byte[] encrypted = RSA_Encrypt(data, keyPair.Public);

        Console.WriteLine("Data: {0}", UTF8Encoding.UTF8.GetString(data));
        Console.WriteLine("Encrypted: {0}", BitConverter.ToString(encrypted));

        // Decrypt the data
        byte[] decrypted = RSA_Decrypt(encrypted, keyPair.Private);
        Console.WriteLine("Decrypted: {0}", UTF8Encoding.UTF8.GetString(decrypted));
    }

    public AsymmetricCipherKeyPair RSA_GenerateKeyPair()
    {
        // Set up the parameters for key generation
        var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), 2048);
        var keyPairGenerator = new RsaKeyPairGenerator();

        keyPairGenerator.Init(keyGenerationParameters);

        // Generate the key pair
        return keyPairGenerator.GenerateKeyPair();
    }

    public byte[] RSA_Encrypt(byte[] data, AsymmetricKeyParameter publicKey)
    {
        // Create the cipher
        var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

        // Initialize the cipher with the public key
        cipher.Init(true, publicKey);

        // Encrypt the data
        return cipher.DoFinal(data);
    }

    public byte[] RSA_Decrypt(byte[] data, AsymmetricKeyParameter privateKey)
    {
        // Create the cipher
        var cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");

        // Initialize the cipher with the private key
        cipher.Init(false, privateKey);

        // Decrypt the data
        return cipher.DoFinal(data);
    }
}

public class EdDSA_06
{
    public void EdDSA_Print()
    {
        // Generate a key pair
        var keyPair = EdDSA_GenerateKeyPair();

        // Sign some data
        byte[] data = UTF8Encoding.UTF8.GetBytes("Hello, World!");
        byte[] signature = EdDSA_Sign(data, keyPair);

        // Verify the signature
        bool verified = EdDSA_Verify(data, signature, keyPair.Public);
        Console.WriteLine("Signature Verified: {0}", verified);
    }

    public AsymmetricCipherKeyPair EdDSA_GenerateKeyPair()
    {
        // Set up the parameters for key generation
        var keyGenerationParameters = new Ed25519KeyGenerationParameters(new SecureRandom());
        var keyPairGenerator = new Ed25519KeyPairGenerator();

        keyPairGenerator.Init(keyGenerationParameters);

        // Generate the key pair
        return keyPairGenerator.GenerateKeyPair();
    }

    public byte[] EdDSA_Sign(byte[] data, AsymmetricCipherKeyPair keyPair)
    {
        // Create the signer
        var signer = new Ed25519Signer();

        // Initialize the signer with the private key
        signer.Init(true, keyPair.Private);

        // Sign the data
        signer.BlockUpdate(data, 0, data.Length);

        // Return the signature
        return signer.GenerateSignature();
    }

    public bool EdDSA_Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey)
    {
        // Create the verifier
        var verifier = new Ed25519Signer();

        // Initialize the verifier with the public key
        verifier.Init(false, publicKey);

        // Verify the signature
        verifier.BlockUpdate(data, 0, data.Length);

        // Return the result
        return verifier.VerifySignature(signature);
    }
}

/// <summary>
/// Diffie-Hellman key exchange
/// </summary>
public class DHKE_05
{
    public void DHKE_Print()
    {
        // Generate key pairs for Alice and Bob
        var aliceKeyPair = DHKE_GenerateKeyPair();
        var bobKeyPair = DHKE_GenerateKeyPair();

        // Exchange public keys and compute shared secrets
        var aliceSharedSecret = DHKE_ComputeSharedSecret(aliceKeyPair, (X25519PublicKeyParameters)bobKeyPair.Public);
        var bobSharedSecret = DHKE_ComputeSharedSecret(bobKeyPair, (X25519PublicKeyParameters)aliceKeyPair.Public);

        // The shared secrets should be the same
        Console.WriteLine("Alice's Shared Secret: " + BitConverter.ToString(aliceSharedSecret));
        Console.WriteLine("Bob's Shared Secret: " + BitConverter.ToString(bobSharedSecret));
    }

    public static AsymmetricCipherKeyPair DHKE_GenerateKeyPair()
    {
        // Set up the parameters for key generation
        var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), 256);
        var keyPairGenerator = new X25519KeyPairGenerator();

        keyPairGenerator.Init(keyGenerationParameters);

        // Generate the key pair
        return keyPairGenerator.GenerateKeyPair();
    }

    public static byte[] DHKE_ComputeSharedSecret(AsymmetricCipherKeyPair ownKeyPair, X25519PublicKeyParameters otherPartyPublicKey)
    {
        // Create the agreement computation object
        var agreement = new X25519Agreement();

        // Buffer to hold the shared secret
        byte[] sharedSecret = new byte[agreement.AgreementSize];

        // Initialize the agreement with the private key
        agreement.Init(ownKeyPair.Private);

        // Compute the shared secret
        agreement.CalculateAgreement(otherPartyPublicKey, sharedSecret, 0);

        return sharedSecret;
    }
}

public class MAC_04
{
    public void MAC_Print()
    {
        // Generate a random key and some data at the sender
        byte[] key = new CRNG_01().CRNG();
        byte[] data = UTF8Encoding.UTF8.GetBytes("Hello, World!");

        // Generate a MAC using the key and data at the sender
        byte[] mac = HMAC_SHA256(key, data);
        Console.WriteLine("HMAC-SHA256 Hash: {0}", BitConverter.ToString(mac));

        // Transport the key, data, and MAC to the receiver...

        // Verify the MAC using the key and data at the receiver
        bool verified = HMAC_SHA256_Verify(key, data, mac);
        Console.WriteLine("MAC Verified: {0}", verified);
    }

    public bool HMAC_SHA256_Verify(byte[] key, byte[] data, byte[] mac)
    {
        byte[] hash = HMAC_SHA256(key, data);
        return hash.SequenceEqual(mac);
    }

    public byte[] HMAC_SHA256(byte[] key, byte[] data)
    {
        return new HMACSHA256(key).ComputeHash(data);
    }
}

public class SHA512_03
{
    public void SHA512_Print()
    {
        byte[] data = UTF8Encoding.UTF8.GetBytes("Hello, World!");
        byte[] hash = SHA512_Hash(data);
        Console.WriteLine("Hash: {0}", BitConverter.ToString(hash));
    }

    public byte[] SHA512_Hash(byte[] data)
    {
        return SHA512.Create().ComputeHash(data);
    }
}

public class AES_02
{
    public void AES_Print()
    {
        byte[] key = new CRNG_01().CRNG();
        byte[] iv = RandomNumberGenerator.GetBytes(12);
        byte[] data = UTF8Encoding.UTF8.GetBytes("Hello, World!");

        byte[] auth_tag_out = new byte[256];
        int auth_tag_length = 0;

        // Encrypt the data and get the authentication tag
        byte[] encrypted = AES_GCM_Encrypt(data, key, iv, out auth_tag_out, out auth_tag_length);

        // Extract the authentication tag from the output buffer
        byte[] auth_tag = new byte[auth_tag_length];
        Buffer.BlockCopy(auth_tag_out, 0, auth_tag, 0, auth_tag_length);

        // Decrypt the data using the authentication tag, key, and IV
        byte[] decrypted = AES_GCM_Decrypt(encrypted, key, iv, auth_tag);

        Console.WriteLine("Original: {0} {1}", BitConverter.ToString(data), UTF8Encoding.UTF8.GetString(data));
        Console.WriteLine("Encrypted: {0}", BitConverter.ToString(encrypted));
        Console.WriteLine("Decrypted: {0} {1}", BitConverter.ToString(decrypted), UTF8Encoding.UTF8.GetString(decrypted));
    }

    public byte[] AES_GCM_Encrypt(byte[] data, byte[] key, byte[] iv, out byte[] auth_tag, out int auth_tag_length)
    {
        using (AesGcm aes_gcm = new AesGcm(key))
        {

            // Output buffer for the encrypted data & the authentication tag
            byte[] encrypted = new byte[data.Length];
            byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

            // Encrypt the data and get the authentication tag
            aes_gcm.Encrypt(iv, data, encrypted, tag);

            // Return the encrypted data and the authentication tag
            auth_tag = tag;
            auth_tag_length = tag.Length;
            return encrypted;
        }
    }

    public byte[] AES_GCM_Decrypt(byte[] data, byte[] key, byte[] iv, byte[] auth_tag)
    {
        using (AesGcm aes_gcm = new AesGcm(key))
        {
            // Output buffer for the decrypted data
            byte[] decrypted = new byte[data.Length];

            // Decrypt the data using the authentication tag, key, and IV
            aes_gcm.Decrypt(iv, data, auth_tag, decrypted);
            return decrypted;
        }
    }
}

public class CRNG_01
{
    public byte[] CRNG()
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] randomValue = new byte[32];

        rng.GetBytes(randomValue);

        return randomValue;
    }
    public void CRNG_Print()
    {
        byte[] randomValue = CRNG();

        // Print the random value as a hex string
        Console.Write("0x");
        foreach (byte b in randomValue)
        {
            Console.Write("{0:X}", b);
        }
    }
}

public class Tomfoolery
{
    public void AsciiRot13()
    {
        for (int i = 48; i < 128; i++)
        {
            Console.Write(Encoding.ASCII.GetString(new byte[] { Convert.ToByte(i) }));
        }
        Console.WriteLine();
        for (int i = 48; i < 128; i++)
        {
            Console.Write(Encoding.ASCII.GetString(new byte[] { Convert.ToByte(i + 13) }));
        }
    }
}

