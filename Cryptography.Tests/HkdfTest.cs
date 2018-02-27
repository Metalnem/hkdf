using System;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Cryptography.Tests
{
	public class HkdfTest
	{
		[Fact]
		public void TestGetBytes()
		{
			var path = File.ReadAllText($"../../../Examples.json");
			var examples = JObject.Parse(path);

			foreach (var example in examples["examples"])
			{
				var hash = (string)example["hash"];
				var ikm = HexDecode((string)example["ikm"]);
				var salt = HexDecode((string)example["salt"]);
				var info = HexDecode((string)example["info"]);

				using (var hkdf = CreateHkdf(hash, ikm, salt, info))
				{
					var data = new byte[(int)example["length"]];
					hkdf.GetBytes(data);

					var expected = (string)example["okm"];
					var actual = HexEncode(data);

					Assert.Equal(expected, actual);
				}
			}
		}

		[Fact]
		public void TestHkdfLimit()
		{
			using (var hkdf = Hkdf.CreateSha256Hkdf(null, null, null))
			{
				hkdf.GetBytes(new byte[32 * 255]);
				Assert.Throws<CryptographicException>(() => hkdf.GetBytes(new byte[1]));
			}
		}

		private static Hkdf CreateHkdf(string algorithm, byte[] ikm, byte[] salt, byte[] info)
		{
			switch (algorithm)
			{
				case "SHA-1": return Hkdf.CreateSha1Hkdf(ikm, salt, info);
				case "SHA-256": return Hkdf.CreateSha256Hkdf(ikm, salt, info);
				default: throw new ArgumentException("Unknown algorithm.");
			}
		}

		private static string HexEncode(byte[] raw)
		{
			return BitConverter.ToString(raw).Replace("-", String.Empty).ToLowerInvariant();
		}

		private static byte[] HexDecode(string hex)
		{
			byte[] raw = new byte[hex.Length / 2];

			for (int i = 0; i < raw.Length; ++i)
			{
				raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
			}

			return raw;
		}
	}
}
