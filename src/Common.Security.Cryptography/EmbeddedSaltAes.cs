using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

/*****************************************************************************\
	This file is shared via SVN externals to the following libraries:
	- CL.Enterprise.Components.SQLCLR
\*****************************************************************************/
namespace Common.Security.Cryptography
{
	/// <summary>
	/// Provides de/ciphering for plain text strings from/to a hex encoded cipher string that contains the initialization vector part of the key.
	/// This provides essentially randomized encryptions, providing highly obfuscated cipher values.
	/// </summary>
	public class EmbeddedSaltAes
	{
		public static char[] HexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

		AesManaged _algorithm;

		/// <summary>
		/// 
		/// </summary>
		/// <param name="key">128 bit key represented as a 16 character hex string.</param>
		public EmbeddedSaltAes(string key)
		{
			_algorithm = MakeAlgorithm(key);
		}

		private AesManaged MakeAlgorithm(string key)
		{
			if(key.Length != 32)
			{
				throw new ArgumentException("Invalid key length.", "key");
			}
			Regex keyExpression = new Regex("[0-9A-Fa-f]{32}", RegexOptions.Compiled);
			if(!keyExpression.IsMatch(key))
			{
				throw new ArgumentException("Invalid characters in key.", "key");
			}

			AesManaged Alg = new AesManaged();
			string KeyTemp = string.Empty;
			Int16 iCount = 0;
			Int16 iLen = (Int16)(key.Length / 2);
			byte[] RealKey = new byte[iLen];

			while(iCount < key.Length)
			{
				KeyTemp = key.Substring(iCount, 2);
				RealKey[iCount / 2] = Convert.ToByte(int.Parse(KeyTemp, NumberStyles.HexNumber));
				iCount += 2;
			}

			Alg.Key = RealKey;
			Alg.Padding = PaddingMode.PKCS7;
			Alg.Mode = CipherMode.CBC;
			Alg.BlockSize = 128;
			return Alg;
		}

		/// <summary>
		/// Encrypts a plain text string into a hex encoded cipher.
		/// </summary>
		/// <param name="plainText"></param>
		/// <returns></returns>
		public string Encrypt(string plainText)
		{
			ICryptoTransform cryptor;
			string strCipherText;

			// Explicitly generate a new random initialization vector for each encryption.
			_algorithm.GenerateIV();
			cryptor = _algorithm.CreateEncryptor();

			if(_algorithm.IV.Length != 16)
			{
				throw new ApplicationException("Incorrect IV length!");
			}

			char[] plainTextChars = plainText.ToCharArray();
			byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainTextChars);

			if(plainTextChars == null || plainTextChars.Length == 0)
			{
				throw new ApplicationException("No input bytes!");
			}

			using(MemoryStream memoryStream = new MemoryStream())
			{
				using(CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptor, CryptoStreamMode.Write))
				{
					using(StreamWriter streamWriter = new StreamWriter(cryptoStream))
					{
						cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
						cryptoStream.FlushFinalBlock();
						byte[] cipherBytes = memoryStream.ToArray();
						memoryStream.Close();
						cryptoStream.Close();

						//if(cipherBytes == null || cipherBytes[0] == '\0') patch for no encrypted bytes! - KYTS-13859
                        if (cipherBytes == null)
						{
							throw new ApplicationException("No encrypted bytes!");
						}

						byte[] combinedBytes = CombineBytes(_algorithm.IV, cipherBytes);
						strCipherText = ConvertToHex(combinedBytes);
					}
				}
			}
			return strCipherText;
		}

		/// <summary>
		/// Decrypts a hex encoded ciphered string into plain text.
		/// </summary>
		/// <param name="encryptedText"></param>
		/// <returns></returns>
		public string Decrypt(string encryptedText)
		{
			byte[] bytCipher = ConvertFromHex(encryptedText);

			ICryptoTransform decryptor = _algorithm.CreateDecryptor();

			using(MemoryStream memStream = new MemoryStream())
			{
				using(CryptoStream cryptStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Write))
				{
					cryptStream.Write(bytCipher, 0, bytCipher.Length);
					cryptStream.FlushFinalBlock();
					byte[] clearBytes = memStream.ToArray();

					//Finally, trim the IV and return:
					return Encoding.UTF8.GetString(clearBytes, _algorithm.IV.Length, clearBytes.Length - _algorithm.IV.Length);
				}
			}
		}

		/// <summary>
		/// Combines two byte arrays.
		/// </summary>
		/// <param name="arrays"></param>
		/// <returns></returns>
		private byte[] CombineBytes(params byte[][] arrays)
		{
			int intOffset = 0;
			long lngSumLength = 0;

			foreach(byte[] a in arrays)
			{
				lngSumLength += a.Length;
			}

			byte[] bytResult = new byte[lngSumLength];

			foreach(byte[] bytArr in arrays)
			{
				Buffer.BlockCopy(bytArr, 0, bytResult, intOffset, bytArr.Length);
				intOffset += bytArr.Length;
			}

			return bytResult;
		}

		/// <summary>
		/// Converts binary data to a hex string.
		/// </summary>
		/// <param name="ByteArray">Byte array containing the data to be converted.</param>
		/// <returns>String containing the hexadecimal representation of the binary data.</returns>
		private string ConvertToHex(byte[] byteArray)
		{
			//create new char array twice as big as old array
			//2 hex characters = 1 byte (8 bits) of data
			//ie: FF = 1111 1111
			char[] chars = new char[byteArray.Length * 2];

			//loop to convert each byte to hex equivalent
			for(int i = 0; i < byteArray.Length; i++)
			{
				int b = byteArray[i];
				chars[i * 2] = HexDigits[b >> 4];
				chars[i * 2 + 1] = HexDigits[b & 0xF];
			}

			return new string(chars);
		}

		/// <summary>
		/// Converts a string of hex characters into a byte array.
		/// </summary>
		/// <param name="hexText"></param>
		/// <returns></returns>
		private byte[] ConvertFromHex(string hexText)
		{
			Int16 count = 0;
			Int16 length = (Int16)(hexText.Length / 2);
			byte[] bytes = new byte[length];

			while (count < hexText.Length)
			{
				string nextPair = hexText.Substring(count, 2);
				int nextInt = 0;
				bool Parsed = int.TryParse(nextPair, NumberStyles.HexNumber, null, out nextInt);

				if (Parsed)
				{
					bytes[count / 2] = Convert.ToByte(nextInt);
				}
				else
				{
					throw new Exception(string.Format("Unable to parse input hex pair '{0}' in string '{1}'", nextPair, hexText));
				}

				count += 2;
			}

			return bytes;
		}

	}
}
