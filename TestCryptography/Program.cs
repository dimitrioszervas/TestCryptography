using System.Security.Cryptography;
using System.Text;

internal class Program
{
    private enum KeyType
    {
        SIGN,
        ENCRYPT
    }

    
  

    private static List<byte[]> GenerateNKeys(int n, byte[] src, KeyType type, byte[] baseKey)
    {
        List<byte[]> keys = new List<byte[]>();
        byte[] salt, info;

        if (type == KeyType.SIGN)
        {
            salt = src; // salt needed to generate keys
            info = Encoding.UTF8.GetBytes("signs");
        }
        else
        {

            salt = src; // salt needed to generate keys
            info = Encoding.UTF8.GetBytes("encrypts");
        }

        for (int i = 0; i < n; i++)
        {
            byte[] key = HKDF.DeriveKey(HashAlgorithmName.SHA256, baseKey, 32, salt, info);
            keys.Add(key);
        }

        return keys;
    }

    public static string ByteArrayToString(byte[] bytes)
    {
        var sb = new StringBuilder("[");
        sb.Append(string.Join(", ", bytes));
        sb.Append("]");
        return sb.ToString();
    }

    private static void Main(string[] args)
    {
        string secretString = "secret";
        string saltString = "";
       
            
        Console.WriteLine($"secret string: {secretString}");
        Console.WriteLine();

        byte[] secret = Encoding.UTF8.GetBytes(secretString);
        byte[] salt = Encoding.UTF8.GetBytes(saltString);
       

        Console.WriteLine($"secret: {ByteArrayToString(secret)}");
        Console.WriteLine();

        byte[] src = HKDF.DeriveKey(hashAlgorithmName: HashAlgorithmName.SHA256,
                                    ikm: secret,
                                    outputLength: 8,
                                    salt: salt,
                                    info: Encoding.UTF8.GetBytes("src"));
        
        salt = src;
        
        Console.WriteLine($"src: {ByteArrayToString(src)}");
        Console.WriteLine();

        byte[] sign = HKDF.DeriveKey(hashAlgorithmName: HashAlgorithmName.SHA256,
                                     ikm: secret,
                                     outputLength: 32,
                                     salt: salt,
                                     info: Encoding.UTF8.GetBytes("sign"));

        Console.WriteLine($"sign: {ByteArrayToString(sign)}");
        Console.WriteLine();

        byte[] encrypt = HKDF.DeriveKey(hashAlgorithmName: HashAlgorithmName.SHA256,
                                       ikm: secret,
                                       outputLength: 32,
                                       salt: salt,
                                       info: Encoding.UTF8.GetBytes("encrypt"));

        Console.WriteLine($"encrypt: {ByteArrayToString(encrypt)}");
        Console.WriteLine();

        int n = 3;
        List<byte[]> encrypts = GenerateNKeys(n, salt, KeyType.ENCRYPT, encrypt);
        List<byte[]> signs = GenerateNKeys(n, salt, KeyType.SIGN, sign);

        Console.WriteLine("encrypts:");
        for (int i = 0; i < encrypts.Count; i++)
        {
            Console.WriteLine($"encryts[{i}] Key: {ByteArrayToString(encrypts[i])}");
            Console.WriteLine();
        }

        Console.WriteLine("signs:");
        for (int i = 0; i < signs.Count; i++)
        {
            Console.WriteLine($"signs[{i}] Key: {ByteArrayToString(signs[i])}");
            Console.WriteLine();
        }
    }
}