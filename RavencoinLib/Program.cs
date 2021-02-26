using NBitcoin;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.IO;

namespace Ravencoin
{
    class Ravencoin
    {
        public static String sBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        static int loops = 100;
        static int eachLoops = 100000;

        public static void Main()
        {
            for (int i = 0; i < loops; i++)
            {
                Console.WriteLine(DateTime.Now);
                StringBuilder sb = new StringBuilder();
                for (int j = 0; j < eachLoops; j++)
                {
                    sb.Append(generateAddress());
                }
                double timeStamp = (DateTime.Now.ToUniversalTime() - new DateTime(1970, 1, 1)).TotalSeconds;
                string filename = @"D:\TEMP\ravenaddress\genadd-" + i.ToString() + "-" + timeStamp.ToString() + ".csv";
                Console.WriteLine(DateTime.Now);
                Console.WriteLine("Writing " + eachLoops.ToString() + " address to '" + filename + "'");
                File.WriteAllText(filename, sb.ToString());
                
            }

            //Console.ReadLine();
        }

        public static string generateAddress()
        {
            // Currently we get PrivateKey and PubKey and Wif from the NBitcoin library. Haven't written my own code yet.
            // https://github.com/MetacoSA/NBitcoin (available from the Nu-Get package manager)

            Key privateKey = new Key(); // generate a random private key
            BitcoinSecret wif = privateKey.GetWif(Network.Main);
            PubKey pubKey = privateKey.PubKey;
            string publicKey = pubKey.ToString(); //"03c18bc24ea4b6e1fc08c356f436d9ffaca4f583c0adc0c83a36b3a1b3abeef762";
            //Console.WriteLine("Publickey: " + publicKey);
            
            //var hash = getHashSha256(publicKeyHex);
            var hash = getHash("sha256",publicKey);
            //Console.WriteLine("hash:" + hash);
            //Console.ReadLine();

            //RIPEMD160 r = RIPEMD160Managed.Create("SHA256");
            string hashed = getHash("ripemd160", hash);

            //Console.WriteLine("hashed:" + hashed);
            hashed = "3c" + hashed;
            //Console.WriteLine("<hashed:" + hashed);
            //Console.ReadLine();

            string newhash1 = getHash("sha256",hashed);
            string newhash2 = getHash("sha256",newhash1);
            string checksum = newhash2.Substring(0, 8); // 4 hex-bytes = 8 characters
            //Console.WriteLine("first hash256: " + newhash1);
            //Console.WriteLine("2nd   hash256: " + newhash2);
            //Console.WriteLine("Checksum: " + checksum);
            //Console.ReadLine();

            string withChecksum = hashed + checksum;
            string address = ConvertToBase58(withChecksum);


            //Console.WriteLine(address);

            //var r = ripemd160(Crypto.SHA256(Crypto.util.hexToBytes(h), { asBytes: true}));
            //r.unshift(byte || coinjs.pub);
            //var hash = Crypto.SHA256(Crypto.SHA256(r, { asBytes: true}), { asBytes: true});
            //var checksum = hash.slice(0, 4);
            //return coinjs.base58encode(r.concat(checksum))
                        
            return (wif+","+privateKey.ToHex()+","+pubKey.Decompress().ToString()+","+address+"\n");
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            if (String.IsNullOrWhiteSpace(hex))
                return new byte[0];

            hex = Regex.Replace(hex, "[\\s-\\{}]", "");

            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits.");

            if (!Regex.IsMatch(hex, "(^|\\A)[0-9A-Fa-f]*(\\Z|$)"))
                throw new Exception("Not hex.");

            byte[] arr = new byte[hex.Length >> 1];

            hex = hex.ToUpper();

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static byte[] StringToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            //For uppercase A-F letters:
            //return val - (val < 58 ? 48 : 55);
            //For lowercase a-f letters:
            //return val - (val < 58 ? 48 : 87);
            //Or the two combined, but a bit slower:
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }


        static string ConvertToBase58(string hash, int numbase = 16)
        {
            BigInteger x;
            if (numbase == 16 && hash.Substring(0, 2) == "0x")
            {
                x = BigInteger.Parse(hash.Substring(2), NumberStyles.HexNumber);
            }
            else
            {
                x = BigInteger.Parse(hash, NumberStyles.HexNumber);
            }

            StringBuilder sb = new StringBuilder();
            while (x > 0)
            {
                BigInteger r = x % 58;
                sb.Append(sBase58Alphabet[(int)r]);
                x = x / 58;
            }

            char[] ca = sb.ToString().ToCharArray();
            Array.Reverse(ca);
            return new string(ca);
        }

        public static string getHash(string method, string text)
        {
            byte[] bytes = StringToByteArray(text);
            string hashString = "";
            if (method.Equals("sha256"))
            {
                SHA256Managed hashMethod = new SHA256Managed();
                hashString = getHashStringFromBytes(hashMethod.ComputeHash(bytes));
            }
            else if (method.Equals("ripemd160"))
            {
                RIPEMD160 hashMethod = RIPEMD160Managed.Create();
                hashString = getHashStringFromBytes(hashMethod.ComputeHash(bytes));
            }

            return hashString;
        }

        public static string getHashStringFromBytes(byte[] bytes)
        {
            string hashString = string.Empty;
            foreach (byte x in bytes)
            {
                hashString += String.Format("{0:x2}", x);
            }

            return (hashString);
        }

    }


}
