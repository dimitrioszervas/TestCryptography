using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using TestCryptography;

internal class Program
{
    public static byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] src, byte[] tag)
    {
        var ciphertext = encryptedData;// encryptedData[0..^16];
        //var tag = new byte[16];// encryptedData[^16..];
        byte[] decrytedBytes = new byte[ciphertext.Length];
        try
        {
            var aes = new AesGcm(key);
            
            byte[] iv = new byte[12];
            Array.Copy(src, iv, 8);

            aes.Decrypt(iv, ciphertext, tag, decrytedBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            Console.WriteLine(ex.StackTrace);
        }

        return decrytedBytes;
    }

    public static void Encrypt(byte[] plainBytes, byte[] key, byte[] src, ref byte[] ciphertext, ref byte[] tag)
    {
        var aes = new AesGcm(key);

        byte[] iv = new byte[12];
        Array.Copy(src, iv, 8);
        
        aes.Encrypt(iv, plainBytes, ciphertext, tag);       
    } 

    private static void Main(string[] args)
    {
        string secretString = "secret";
      
        int n = 3;
        List<byte[]> encrypts = new List<byte[]>();
        List<byte[]> signs = new List<byte[]>();
        byte[] src = new byte[8];

        KeyDerivation.GenerateKeys(ref encrypts, ref signs, ref src, secretString, n);

        Console.WriteLine("encrypts:");
        for (int i = 0; i < encrypts.Count; i++)
        {
            Console.WriteLine($"encryts[{i}] Key: {KeyDerivation.ByteArrayToString(encrypts[i])}");
            Console.WriteLine();
        }

        Console.WriteLine("signs:");
        for (int i = 0; i < signs.Count; i++)
        {
            Console.WriteLine($"signs[{i}] Key: {KeyDerivation.ByteArrayToString(signs[i])}");
            Console.WriteLine();
        }

        var data = "Test Ecryption";
        var dataBytes = Encoding.UTF8.GetBytes(data);

        Console.WriteLine($"Data bytes: {KeyDerivation.ByteArrayToString(dataBytes)}");

        byte[] encryptedShard = new byte[dataBytes.Length];
        byte[] tag = new byte[16];
        Encrypt(dataBytes, encrypts[1], src, ref encryptedShard, ref tag);

        Console.WriteLine($"Encrypted bytes: {KeyDerivation.ByteArrayToString(encryptedShard)}");
        Console.WriteLine($"Calculated Tag: {KeyDerivation.ByteArrayToString(tag)}");

        var decryptedShard = Decrypt(encryptedShard, encrypts[1], src, tag);

        Console.WriteLine($"Decrypted bytes: {KeyDerivation.ByteArrayToString(decryptedShard)}");
    }
}