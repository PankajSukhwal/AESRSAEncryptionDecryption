using PayloadEncDec;

namespace TestEncDec
{
    internal class Program
    {
        static void Main(string[] args)
        {
            #region AES

            Console.WriteLine("---------- AES Encryption/Decryption ----------");
            Console.WriteLine("Enter text to be encrypted: ");
            string? plainText = Console.ReadLine();

            //pass keyInitializerStr to AESCryptor, could be anything
            AESCryptor aesCryptor = new AESCryptor("KeyEncDec");

            var cipherText = aesCryptor.Encrypt(plainText, out string iv, out string key);
            Console.WriteLine("\nCipher Text : " + cipherText);
            Console.WriteLine("IV : " + iv);
            Console.WriteLine("Key : " + key);

            var decryptedText = aesCryptor.Decrypt(cipherText, iv, key);
            Console.WriteLine("\nDecrypted Text : " + decryptedText);

            #endregion AES

            #region RSA

            Console.WriteLine("\n---------- RSA Encryption/Decryption with Digital Signature ----------");
            Console.WriteLine("Enter text to be encrypted: ");
            string? plainText1 = Console.ReadLine();

            //Generating Public/Private keys for any client
            RSACryptor rsaCryptor = new RSACryptor();
            rsaCryptor.GeneratePublicPrivateKeys(out string publicKey, out string privateKey);
            Console.WriteLine("\nPublic Key : "+ publicKey);
            Console.WriteLine("Private Key : " + privateKey);

            var cipherText1 = rsaCryptor.RSAEncrypt(publicKey, privateKey, plainText1, out string signature);
            Console.WriteLine("\nCipher Text : " + cipherText1);
            Console.WriteLine("Signature : " + signature);

            var decryptedText1 = rsaCryptor.RSADecrypt(publicKey, privateKey, cipherText1, signature);
            Console.WriteLine("\nDecrypted Text : " + decryptedText1);

            #endregion RSA
        }
    }
}
