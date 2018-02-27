using System;
using System.Security.Cryptography;

namespace Cryptography
{
	/// <summary>
	/// HMAC-based Extract-and-Expand Key Derivation Function, defined in
	/// <see href="https://tools.ietf.org/html/rfc5869">RFC 5869</see>.
	/// </summary>
	public sealed class Hkdf : IDisposable
	{
		private const byte MaxOutputLength = 255;
		private static readonly byte[] Empty = new byte[0];

		private readonly HMAC hmac;
		private readonly byte[] info;
		private readonly int size;

		private byte[] previous;
		private ArraySegment<byte> cache;
		private byte[] counter;
		private bool disposed;

		private Hkdf(HMAC hmac, byte[] ikm, byte[] info)
		{
			ikm = ikm ?? Empty;
			info = info ?? Empty;

			hmac.TransformFinalBlock(ikm, 0, ikm.Length);
			hmac.Key = hmac.Hash;

			this.hmac = hmac;
			this.info = info;

			size = hmac.HashSize / 8;
			previous = Empty;
			cache = new ArraySegment<byte>(Empty);
			counter = new byte[] { 1 };
		}

		/// <summary>
		/// Initializes a new instance of the HKDF algorithm using the SHA-1 hash function.
		/// </summary>
		/// <param name="ikm">Input keying material.</param>
		/// <param name="salt">Optional salt value (a non-secret random value).</param>
		/// <param name="info">Optional context and application specific information.</param>
		/// <returns>An HKDF instance.</returns>
		internal static Hkdf CreateSha1Hkdf(byte[] ikm, byte[] salt, byte[] info)
		{
			return new Hkdf(new HMACSHA1(salt ?? Empty), ikm, info);
		}

		/// <summary>
		/// Initializes a new instance of the HKDF algorithm using the SHA-256 hash function.
		/// </summary>
		/// <param name="ikm">Input keying material.</param>
		/// <param name="salt">Optional salt value (a non-secret random value).</param>
		/// <param name="info">Optional context and application specific information.</param>
		/// <returns>An HKDF instance.</returns>
		public static Hkdf CreateSha256Hkdf(byte[] ikm, byte[] salt, byte[] info)
		{
			return new Hkdf(new HMACSHA256(salt ?? Empty), ikm, info);
		}

		/// <summary>
		/// Initializes a new instance of the HKDF algorithm using the SHA-512 hash function.
		/// </summary>
		/// <param name="ikm">Input keying material.</param>
		/// <param name="salt">Optional salt value (a non-secret random value).</param>
		/// <param name="info">Optional context and application specific information.</param>
		/// <returns>An HKDF instance.</returns>
		public static Hkdf CreateSha512Hkdf(byte[] ikm, byte[] salt, byte[] info)
		{
			return new Hkdf(new HMACSHA512(salt ?? Empty), ikm, info);
		}

		/// <summary>
		/// Expand the input keying material into the output keying material.
		/// </summary>
		/// <param name="data">Output destination.</param>
		public void GetBytes(byte[] data)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(Hkdf));
			}

			if (data == null)
			{
				throw new ArgumentNullException(nameof(data));
			}

			int needed = data.Length;
			int left = cache.Count + (byte)(MaxOutputLength - counter[0] + 1) * size;

			if (left < needed)
			{
				throw new CryptographicException($"Output length has exceeded {MaxOutputLength} blocks ({size * MaxOutputLength} bytes).");
			}

			var seg = new ArraySegment<byte>(data);
			var n = Copy(cache, seg);

			while (seg.Count > 0)
			{
				hmac.TransformBlock(previous, 0, previous.Length, previous, 0);
				hmac.TransformBlock(info, 0, info.Length, info, 0);
				hmac.TransformFinalBlock(counter, 0, counter.Length);

				previous = hmac.Hash;
				cache = new ArraySegment<byte>(previous);
				++counter[0];

				n = Copy(cache, seg);
				seg = Slice(seg, n);
			}

			cache = Slice(cache, n);
		}

		private static int Copy(ArraySegment<byte> source, ArraySegment<byte> destination)
		{
			int n = Math.Min(source.Count, destination.Count);
			Array.Copy(source.Array, source.Offset, destination.Array, destination.Offset, n);

			return n;
		}

		private static ArraySegment<byte> Slice(ArraySegment<byte> seg, int index)
		{
			return new ArraySegment<byte>(seg.Array, seg.Offset + index, seg.Count - index);
		}

		public void Dispose()
		{
			if (!disposed)
			{
				hmac.Dispose();
				disposed = true;
			}
		}
	}
}
