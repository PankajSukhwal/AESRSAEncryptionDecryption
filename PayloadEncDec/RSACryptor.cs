using System;
using System.Security.Cryptography;
using System.Text;

namespace PayloadEncDec
{
    /// <summary>
    /// Class for using RSA encryption/decryption with Digital Signature
    /// </summary>
    public class RSACryptor
    {
        #region Private Variables - RSA Configuration

        UTF8Encoding encoder = new UTF8Encoding();
        private static int rsaLengthLimit = 512;

        #endregion Private Variables - RSA Configuration

        /// <summary>
        /// Generate Public-Private key pair using RSA
        /// </summary>
        /// <param name="out publicKey"></param>
        /// <param name="out privateKey"></param>
        public void GeneratePublicPrivateKeys(out string publicKey, out string privateKey)
        {
            try
            {
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(rsaLengthLimit);
                publicKey = RSA.ToXmlString(false);
                privateKey = RSA.ToXmlString(true);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Encrypts plain text and signs using RSA
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="publicKey"></param>
        /// <param name="plainText"></param>
        /// <param name="out signature"></param>
        /// <returns>Encrypted text</returns>
        public string RSAEncrypt(string publicKey, string privateKey, string plainText, out string signature)
        {
            try
            {
                signature = SignData(plainText, privateKey);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(rsaLengthLimit);
                rsa.FromXmlString(publicKey);
                byte[] contentData = Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = rsa.Encrypt(contentData, false);
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Decrypts encrypted text and verifies signature using RSA
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="encryptedText"></param>
        /// <param name="signature"></param>
        /// <returns>decrypted text</returns>
        public string RSADecrypt(string publicKey, string privateKey, string encryptedText, string signature)
        {
            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(rsaLengthLimit);
                rsa.FromXmlString(privateKey);
                byte[] contentData = Convert.FromBase64String(encryptedText);
                byte[] decrypted = rsa.Decrypt(contentData, false);
                string decryptedString = encoder.GetString(decrypted);
                if (VerifyData(decryptedString, signature, publicKey))
                {
                    return decryptedString;
                }
                return "Signature Verification Failed";
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #region HelperMethods

        /// <summary>
        /// Creates Signature by hashing the plainText with SHA256 and signs the resulting value by privateKey
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="privateKey"></param>
        /// <returns>RSA Signed Message</returns>
        private string SignData(string plainText, string privateKey)
        {
            try
            {
                byte[] signedBytes;
                using (var rsa = new RSACryptoServiceProvider())
                {
                    byte[] originalData = encoder.GetBytes(plainText);
                    try
                    {
                        rsa.FromXmlString(privateKey);
                        signedBytes = rsa.SignData(originalData, new SHA256CryptoServiceProvider());
                    }
                    catch (CryptographicException ex)
                    {
                        throw ex;
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
                return Convert.ToBase64String(signedBytes);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Verifies signature for authenticated source
        /// </summary>
        /// <param name="originalMessage"></param>
        /// <param name="signedMessage"></param>
        /// <param name="publicKey"></param>
        /// <returns>true/false</returns>
        private bool VerifyData(string originalMessage, string signedMessage, string publicKey)
        {
            try
            {
                bool success = false;
                using (var rsa = new RSACryptoServiceProvider())
                {
                    byte[] bytesToVerify = encoder.GetBytes(originalMessage);
                    byte[] signedBytes = Convert.FromBase64String(signedMessage);
                    try
                    {
                        rsa.FromXmlString(publicKey);
                        success = rsa.VerifyData(bytesToVerify, new SHA256CryptoServiceProvider(), signedBytes);
                    }
                    catch (CryptographicException ex)
                    {
                        throw ex;
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
                return success;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #endregion

    }
}
