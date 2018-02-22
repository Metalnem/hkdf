# libhkdf [![Latest Version](https://img.shields.io/nuget/v/libhkdf.svg)](https://www.nuget.org/packages/libhkdf) [![Build Status](https://travis-ci.org/Metalnem/libhkdf.svg?branch=master)](https://travis-ci.org/Metalnem/libhkdf) [![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/metalnem/libhkdf/master/LICENSE)

.NET Standard 2.0 implementation of HMAC-based
Extract-and-Expand Key Derivation Function, defined in
[RFC 5869](https://tools.ietf.org/html/rfc5869).

## Usage

```csharp
var random = RandomNumberGenerator.Create();

// Input keying material
var secret = new byte[] { 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };

// Optional salt value (a non-secret random value)
var salt = new byte[32];
random.GetBytes(salt);

// Optional context and application specific information
var info = new byte[] { 0x69, 0x6e, 0x66, 0x6f };

using (var hkdf = Hkdf.CreateSha256Hkdf(secret, salt, info))
{
  var key = new byte[32];
  hkdf.GetBytes(key);

  var hex = BitConverter.ToString(key).Replace("-", String.Empty);
  Console.WriteLine(hex.ToLowerInvariant());
}
```
