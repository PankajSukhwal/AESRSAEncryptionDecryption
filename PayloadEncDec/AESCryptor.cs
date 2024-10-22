using System;
using System.Security.Cryptography;
using System.Text;

namespace PayloadEncDec
{
    /// <summary>
    /// Class for using AES encryption/decryption
    /// </summary>
    public class AESCryptor
    {
        #region Private Variables - AES Configuration

        UTF8Encoding encoder = new UTF8Encoding();
        AesCryptoServiceProvider cryptoProvider;
        private static int saltLengthLimit = 256;
        private static int blockSize = 128;
        private static int keySize = 256;
        private static CipherMode mode = CipherMode.CBC;
        private static PaddingMode padding = PaddingMode.PKCS7;
        private static int iterations = 300;

        #endregion Private Variables - AES Configuration

        /// <summary>
        /// Initializing AES object and parameters
        /// </summary>
        /// <param name="keyInitializerStr"></param>
        public AESCryptor(string keyInitializerStr)
        {
            cryptoProvider = new AesCryptoServiceProvider();
            cryptoProvider.BlockSize = blockSize;
            cryptoProvider.KeySize = keySize;
            cryptoProvider.Key = CreateKey(keyInitializerStr);
            cryptoProvider.GenerateIV();
            cryptoProvider.Mode = mode;
            cryptoProvider.Padding = padding;
        }

        /// <summary>
        /// Encrypt plainText using AES and returns encryted text alongwith IV/AESKey
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="out iv"></param>
        /// <param name="out key"></param>
        /// <returns>encryted text</returns>
        public string Encrypt(string plainText, out string iv, out string key)
        {
            try
            {
                iv = Convert.ToBase64String(cryptoProvider.IV);
                key = Convert.ToBase64String(cryptoProvider.Key);
                ICryptoTransform transform = cryptoProvider.CreateEncryptor();
                byte[] encryptedBytes = transform.TransformFinalBlock(encoder.GetBytes(plainText), 0, encoder.GetBytes(plainText).Length);
                string encryptedString = Convert.ToBase64String(encryptedBytes);
                return encryptedString;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts the cipherText to plainText using IV and AES key
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="iv"></param>
        /// <param name="key"></param>
        /// <returns>plainText string</returns>
        public string Decrypt(string cipherText, string iv, string key)
        {
            try
            {
                cryptoProvider.IV = Convert.FromBase64String(iv);
                cryptoProvider.Key = Convert.FromBase64String(key);
                ICryptoTransform transform = cryptoProvider.CreateDecryptor();
                byte[] encryptedBytes = Convert.FromBase64String(cipherText);
                byte[] decryptedBytes = transform.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                string decryptedString = encoder.GetString(decryptedBytes);
                return decryptedString;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #region HelperMethods

        /// <summary>
        /// Creates AES key for encryption/decryption
        /// </summary>
        /// <param name="keyInitializerStr"></param>
        /// <param name="keyBytes"></param>
        /// <returns>AES key</returns>
        public static byte[] CreateKey(string keyInitializerStr, int keyBytes = 16)
        {
            try
            {
                //GetSalt method can be used either for default saltLengthLimit provided or with maximumSaltLength via the given methods
                var keyGenerator = new Rfc2898DeriveBytes(keyInitializerStr, GetSalt(), iterations);
                return keyGenerator.GetBytes(keyBytes);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Gets specific salt with specified length
        /// </summary>
        /// <returns>salt</returns>
        private static byte[] GetSalt()
        {
            return GetSalt(saltLengthLimit);
        }

        /// <summary>
        /// Generate salt for specific length
        /// </summary>
        /// <param name="maximumSaltLength"></param>
        /// <returns>salt</returns>
        private static byte[] GetSalt(int maximumSaltLength)
        {
            try
            {
                var salt = new byte[maximumSaltLength];
                using (var random = new RNGCryptoServiceProvider())
                {
                    random.GetNonZeroBytes(salt);
                }
                return salt;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #endregion HelperMethods


    }
}
