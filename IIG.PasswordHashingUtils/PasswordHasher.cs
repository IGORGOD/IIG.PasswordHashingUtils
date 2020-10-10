using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IIG.PasswordHashingUtils
{
    /// <summary>
    ///     Class that Provides Functional for Password Hashing
    /// </summary>
    public class PasswordHasher
    {
        /// <summary>
        ///     Mod Adler Const for Adler32CheckSum
        /// </summary>
        private static uint _modAdler32 = 65521;

        /// <summary>
        ///     First Level Salt
        /// </summary>
        private static string _salt = "put your soul(or salt) here";

        /// <summary>
        ///     Init PasswordHasher Parameters
        /// </summary>
        /// <param name="salt">First Level Salt</param>
        /// <param name="adlerMod32">Mod Adler Const for Adler32CheckSum</param>
        public static void Init(string salt, uint adlerMod32)
        {
            if (!string.IsNullOrEmpty(salt))
                _salt = salt;
            if (adlerMod32 > 0)
                _modAdler32 = adlerMod32;
        }

        /// <summary>
        ///     Calculates Hash for Provided String Password
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="salt">First Level Salt</param>
        /// <param name="adlerMod32">Mod Adler Const for Adler32CheckSum</param>
        /// <returns>SHA2 String Hash for Provided Password</returns>
        public static string GetHash(string password, string salt = null, uint? adlerMod32 = null)
        {
            Init(salt, adlerMod32 ?? 0);
            try
            {
                password.Select(Convert.ToByte).ToArray();
            }
            catch (OverflowException)
            {
                password = Encoding.ASCII.GetString(Encoding.Unicode.GetBytes(password));
            }

            return HashSha2($"{_salt}{Adler32CheckSum(password)}{password}");
        }

        /// <summary>
        ///     Calculates SHA2 Hash for Provided Text
        /// </summary>
        /// <param name="sData">String Data</param>
        /// <returns>String Result of SHA2 Hash for Provided Text</returns>
        private static string HashSha2(string sData)
        {
            return BitConverter.ToString(SHA256.Create().ComputeHash(sData.Select(Convert.ToByte).ToArray()))
                .Replace("-", "");
        }

        /// <summary>
        ///     Calculates Adler32CheckSum for Provided Text and Parameters
        /// </summary>
        /// <param name="sData">Text</param>
        /// <param name="index">Index Adler32CheckSum Parameter</param>
        /// <param name="length">Length Adler32CheckSum Parameter</param>
        /// <returns>String Representation of Adler32CheckSum Result</returns>
        private static string Adler32CheckSum(string sData, int index = 0, int length = 0)
        {
            if (length < 1)
                length = sData.Length / 2;
            if (index < 0)
                index = 0;

            uint buf = 1;
            uint res = 0;
            var data = sData.Select(Convert.ToByte).ToArray();

            for (var i = index; length > 0; i++, length--)
            {
                buf = (buf + data[i]) % _modAdler32;
                res = (res + buf) % _modAdler32;
            }

            res = (res << 16) | buf;

            return BitConverter.ToString(BitConverter.GetBytes(res)).Replace("-", "");
        }
    }
}