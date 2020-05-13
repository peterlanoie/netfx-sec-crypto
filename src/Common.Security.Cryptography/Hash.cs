using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Common.Security.Cryptography
{
	public class Hash
	{
		public static byte[] StringToHashBytes(string input, HashAlgorithm algorithm)
		{
			var inputBytes = Encoding.ASCII.GetBytes(input);
			return algorithm.ComputeHash(inputBytes);
		}

		public static string StringToHashString(string input, HashAlgorithm algorithm)
		{
			return BytesToHex(StringToHashBytes(input, algorithm));
		}

		public static string BytesToHex(byte[] input)
		{
			// convert byte array to hex string
			var sb = new StringBuilder();
			for(var i = 0; i < input.Length; i++)
			{
				sb.Append(input[i].ToString("X2"));
			}
			return sb.ToString();
		}

		// ReSharper disable InconsistentNaming
		public static string GetMD5Hash(string input)
		{
			return StringToHashString(input, System.Security.Cryptography.MD5.Create());
		}

		public static string GetSHA1Hash(string input)
		{
			return StringToHashString(input, SHA1.Create());
		}

		public static string GetSHA256Hash(string input)
		{
			return StringToHashString(input, SHA256.Create());
		}

		public static string GetSHA384Hash(string input)
		{
			return StringToHashString(input, SHA384.Create());
		}

		public static string GetSHA512Hash(string input)
		{
			return StringToHashString(input, SHA512.Create());
		}

		// ReSharper restore InconsistentNaming
	}
}
