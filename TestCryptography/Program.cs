using System.Security.Cryptography;
using System.Text;
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
    }
}