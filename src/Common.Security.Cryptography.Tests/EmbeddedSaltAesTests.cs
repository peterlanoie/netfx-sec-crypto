using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Common.Security.Cryptography.Tests
{
	[TestClass]
	public class EmbeddedSaltAesTests
	{

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void TestBadKeyLength()
		{
			EmbeddedSaltAes crypto = new EmbeddedSaltAes("0");
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void BadKeyCharTest1()
		{
			EmbeddedSaltAes crypto = new EmbeddedSaltAes("G0000000000000000000000000000000");
		}

		[TestMethod]
		[ExpectedException(typeof(ArgumentException))]
		public void BadKeyCharTest2()
		{
			EmbeddedSaltAes crypto = new EmbeddedSaltAes("g0000000000000000000000000000000");
		}

		[TestMethod]
		[ExpectedException(typeof(ApplicationException))]
		public void EmptyInputTest()
		{
			EmbeddedSaltAes crypto = new EmbeddedSaltAes("00000000000000000000000000000000");
			crypto.Encrypt("");
		}

		[TestMethod]
		public void TestSingleInstanceCrypto()
		{
			string plainTextIn = "Have a Delmar day!";
			string cipherText, plainTextout;
			EmbeddedSaltAes crypto;
			
			crypto = new EmbeddedSaltAes("00000000000000000000000000000000");
			cipherText = crypto.Encrypt(plainTextIn);
			plainTextout = crypto.Decrypt(cipherText);

			Assert.AreEqual(plainTextIn, plainTextout);
		}

		[TestMethod]
		public void TestMultiInstanceCrypto()
		{
			string plainTextIn = "Have a Delmar day!";
			string cipherText, plainTextout;
			EmbeddedSaltAes crypto;

			crypto = new EmbeddedSaltAes("00000000000000000000000000000000");
			cipherText = crypto.Encrypt(plainTextIn);

			crypto = new EmbeddedSaltAes("00000000000000000000000000000000");
			plainTextout = crypto.Decrypt(cipherText);

			Assert.AreEqual(plainTextIn, plainTextout);
		}

		[TestMethod]
		public void TestRandomEncryptions()
		{
			string plainTextIn = "Have a Delmar day!";
			string cipherText1, cipherText2;
			EmbeddedSaltAes crypto;

			crypto = new EmbeddedSaltAes("00000000000000000000000000000000");
			cipherText1 = crypto.Encrypt(plainTextIn);
			cipherText2 = crypto.Encrypt(plainTextIn);

			Assert.AreNotEqual(cipherText1, cipherText2);
		}
	}
}
