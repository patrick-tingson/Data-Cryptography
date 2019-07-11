using Convertion_XXX;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography_XXX
{
    public static class Decrypt
    {
        public static string AesCrypto32(string encryptedKey96, string masterKey32, string iVector16)
        {
            string response = "";
            try
            {
                if (encryptedKey96.Length == 0 || masterKey32.Length == 0 || iVector16.Length == 0)
                {
                    response = "";
                }
                else if (encryptedKey96.Length != 96 || masterKey32.Length != 32 || iVector16.Length != 16)
                {
                    response = "";
                }
                else
                {
                    byte[] bytesEncryptedKey = new byte[48];
                    using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                    {
                        byte[] key = System.Text.Encoding.UTF8.GetBytes(masterKey32);
                        byte[] iv = System.Text.Encoding.UTF8.GetBytes(iVector16);
                        aesAlg.Key = key;
                        aesAlg.IV = iv;

                        bytesEncryptedKey = Convertion.StringToByteArrayBase16(encryptedKey96);

                        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                        using (MemoryStream msDecrypt = new MemoryStream(bytesEncryptedKey))
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {
                                    response = srDecrypt.ReadToEnd();
                                }
                            }
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }

        public static string TripleDES(string encryptedText48, string masterKey16, string iVector8)
        {
            string response = "";
            try
            {
                byte[] bytesEncryptedKey = new byte[24];
                using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
                {
                    byte[] key = System.Text.Encoding.UTF8.GetBytes(masterKey16);
                    byte[] iv = System.Text.Encoding.UTF8.GetBytes(iVector8);
                    tdsAlg.Key = key;
                    tdsAlg.IV = iv;

                    bytesEncryptedKey = Convertion.StringToByteArrayBase16(encryptedText48);

                    ICryptoTransform decryptor = tdsAlg.CreateDecryptor(tdsAlg.Key, tdsAlg.IV);

                    using (MemoryStream msDecrypt = new MemoryStream(bytesEncryptedKey))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                response = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }

        public static string TripleDES16(string encryptedText48, string masterKey16, string iVector8)
        {
            string response = "";
            try
            {
                if (encryptedText48.Length == 0 || masterKey16.Length == 0 || iVector8.Length == 0)
                {
                    response = "";
                }
                else if (encryptedText48.Length != 48 || masterKey16.Length != 16 || iVector8.Length != 8)
                {
                    response = "";
                }
                else
                {
                    byte[] bytesEncryptedKey = new byte[24];
                    using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
                    {
                        byte[] key = System.Text.Encoding.UTF8.GetBytes(masterKey16);
                        byte[] iv = System.Text.Encoding.UTF8.GetBytes(iVector8);
                        tdsAlg.Key = key;
                        tdsAlg.IV = iv;

                        bytesEncryptedKey = Convertion.StringToByteArrayBase16(encryptedText48);

                        ICryptoTransform decryptor = tdsAlg.CreateDecryptor(tdsAlg.Key, tdsAlg.IV);

                        using (MemoryStream msDecrypt = new MemoryStream(bytesEncryptedKey))
                        {
                            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                                {
                                    response = srDecrypt.ReadToEnd();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return response;
        }

        public static string RSA(string plainText, string privateKeyPEM)
        {
            if (plainText.Length == 0)
                throw new InvalidDataException("Invalid Plain Text.");
            if (privateKeyPEM.Length == 0)
                throw new InvalidDataException("Invalid Private Key PEM.");

            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    //Must be BancNet Public Key
                    rsa.LoadPrivateKeyPEM(privateKeyPEM);
                    var resultBytes = Convert.FromBase64String(plainText);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}
