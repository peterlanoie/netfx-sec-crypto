using System;
using System.Text;

namespace Common.Security.Cryptography
{
	[Obsolete("Use 'Hash helper'", true)]
	public class MD5
	{
		[Obsolete("Use 'Hash.GetMD5Hash'", true)]
		public static string CalculateMD5Hash(string input)
		{
			return Hash.GetMD5Hash(input);
		}
	}
}