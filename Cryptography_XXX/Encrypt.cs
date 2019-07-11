using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography_XXX
{
    public static class Encrypt
    {
        public static string AesCrypto32(string plainText32, string masterKey32, string iVector16)
        {
            string response = "";
            try
            {
                if (plainText32.Length == 0 || masterKey32.Length == 0 || iVector16.Length == 0)
                {
                    response = "";
                }
                else if (plainText32.Length != 32 || masterKey32.Length != 32 || iVector16.Length != 16)
                {
                    response = "";
                }
                else
                {
                    byte[] bytesEncryptedKey;

                    using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                    {
                        byte[] key = System.Text.Encoding.UTF8.GetBytes(masterKey32);
                        byte[] iv = System.Text.Encoding.UTF8.GetBytes(iVector16);
                        aesAlg.Key = key;
                        aesAlg.IV = iv;
                        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                        using (MemoryStream msEncrypt = new MemoryStream())
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                using (StreamWriter srEncrypt = new StreamWriter(csEncrypt))
                                {
                                    srEncrypt.Write(plainText32);
                                }
                                bytesEncryptedKey = msEncrypt.ToArray();
                                response = BitConverter.ToString(bytesEncryptedKey).Replace("-", "");
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

        public static string TripleDES16(string plainText16, string masterKey16, string iVector8)
        {
            string response = "";
            try
            {
                if (plainText16.Length == 0 || masterKey16.Length == 0 || iVector8.Length == 0)
                {
                    response = "";
                }
                else if (plainText16.Length != 16 || masterKey16.Length != 16 || iVector8.Length != 8)
                {
                    response = "";
                }
                else
                {
                    byte[] bytesEncryptedKey;

                    using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
                    {
                        byte[] key = System.Text.Encoding.UTF8.GetBytes(masterKey16);
                        byte[] iv = System.Text.Encoding.UTF8.GetBytes(iVector8);
                        tdsAlg.Key = key;
                        tdsAlg.IV = iv;

                        ICryptoTransform encryptor = tdsAlg.CreateEncryptor(tdsAlg.Key, tdsAlg.IV);

                        using (MemoryStream msEncrypt = new MemoryStream())
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            {
                                using (StreamWriter srEncrypt = new StreamWriter(csEncrypt))
                                {
                                    srEncrypt.Write(plainText16);
                                }
                                bytesEncryptedKey = msEncrypt.ToArray();
                                response = BitConverter.ToString(bytesEncryptedKey).Replace("-", "");
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

        public static string TripleDES(string plainText, string masterKey16, string iVector8)
        {
            string response = "";
            try
            {
                byte[] bytesEncryptedKey;
                using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
                {
                    byte[] key = System.Text.Encoding.UTF8.GetBytes(masterKey16);
                    byte[] iv = System.Text.Encoding.UTF8.GetBytes(iVector8);
                    tdsAlg.Key = key;
                    tdsAlg.IV = iv;

                    ICryptoTransform encryptor = tdsAlg.CreateEncryptor(tdsAlg.Key, tdsAlg.IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter srEncrypt = new StreamWriter(csEncrypt))
                            {
                                srEncrypt.Write(plainText);
                            }
                            bytesEncryptedKey = msEncrypt.ToArray();
                            response = BitConverter.ToString(bytesEncryptedKey).Replace("-", "");
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

        public static string RSA(string plainText, string publicKeyPEM)
        {
            if (plainText.Length == 0)
                throw new InvalidDataException("Invalid Plain Text.");
            if (publicKeyPEM.Length == 0)
                throw new InvalidDataException("Invalid Public Key PEM.");

            var bytesData = Encoding.UTF8.GetBytes(plainText);
            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    //Must be BancNet Public Key
                    rsa.LoadPublicKeyPEM(publicKeyPEM);
                    var encryptedData = rsa.Encrypt(bytesData, true);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

    }
}
