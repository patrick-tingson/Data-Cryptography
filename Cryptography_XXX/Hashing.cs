using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography_XXX
{
    public static class Hashing
    {
        public static string MD5(string stringToHash)
        {
            // create hash object
            using (MD5 hasher = new MD5CryptoServiceProvider())
            {
                hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(stringToHash));
                byte[] dbytes = hasher.Hash;
                StringBuilder sBuilder = new StringBuilder();

                for (int n = 0; n <= dbytes.Length - 1; n++)
                {
                    sBuilder.Append(dbytes[n].ToString("X2"));
                }
                return sBuilder.ToString();
            }
        }

        public static string SHA1(string stringToHash)
        {
            System.Security.Cryptography.SHA1Managed sha1Obj = new System.Security.Cryptography.SHA1Managed();
            byte[] bytesToHash = System.Text.Encoding.UTF8.GetBytes(stringToHash);
            bytesToHash = sha1Obj.ComputeHash(bytesToHash);
            return BitConverter.ToString(bytesToHash).Replace("-", "").ToUpper();
        }

        public static string SHA256(string strToHash)
        {
            System.Security.Cryptography.SHA256Managed sha256Obj = new System.Security.Cryptography.SHA256Managed();
            byte[] bytesToHash = System.Text.Encoding.UTF8.GetBytes(strToHash);
            bytesToHash = sha256Obj.ComputeHash(bytesToHash);
            return BitConverter.ToString(bytesToHash).Replace("-", "").ToUpper();
        }
    }
}
