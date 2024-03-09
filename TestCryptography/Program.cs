using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using TestCryptography;

internal class Program
{
 

    private static void Main(string[] args)
    {
        string secretString = "secret";
      
        int n = 3;
        List<byte[]> encrypts = new List<byte[]>();
        List<byte[]> signs = new List<byte[]>();
        byte[] src = new byte[8];

        CryptoUtils.GenerateKeys(ref encrypts, ref signs, ref src, secretString, n);

        Console.WriteLine("encrypts:");
        for (int i = 0; i < encrypts.Count; i++)
        {
            Console.WriteLine($"encryts[{i}] Key: {CryptoUtils.ByteArrayToString(encrypts[i])}");
            Console.WriteLine();
        }

        Console.WriteLine("signs:");
        for (int i = 0; i < signs.Count; i++)
        {
            Console.WriteLine($"signs[{i}] Key: {CryptoUtils.ByteArrayToString(signs[i])}");
            Console.WriteLine();
        }

        var data = "Test Ecryption";
        var dataBytes = Encoding.UTF8.GetBytes(data);

        Console.WriteLine($"Data bytes: {CryptoUtils.ByteArrayToString(dataBytes)}");

        byte[] encryptedShard = new byte[dataBytes.Length];
        byte[] tag = new byte[CryptoUtils.TAG_SIZE];
        CryptoUtils.Encrypt(dataBytes, encrypts[1], src, ref encryptedShard, ref tag);

        Console.WriteLine($"Encrypted bytes: {CryptoUtils.ByteArrayToString(encryptedShard)}");
        Console.WriteLine($"Calculated Tag: {CryptoUtils.ByteArrayToString(tag)}");
        Console.WriteLine();

        var decryptedShard = CryptoUtils.Decrypt(encryptedShard, encrypts[1], src, tag);

        Console.WriteLine($"Decrypted bytes: {CryptoUtils.ByteArrayToString(decryptedShard)}");
    }
}