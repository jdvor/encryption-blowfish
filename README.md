# Encryption.Blowfish

Efficient implementation of [Blowfish][bf] cipher with minimal memory allocations in [ECB][ecb], [CBC][cbc] and [CTR][ctr] block modes.<br />
CTR is also available as encryption and decryption stream.<br />
Non-stream variants works by mutating input buffer (`Span<byte>`).

Implemented using [defaults][bfc], 16-round with pre-computed subkeys.<br />
Tested against well known [test vectors][bftv].

## Quickstart

nuget package Encryption.Blowfish
```shell
dotnet add package Encryption.Blowfish [ -v 1.0.0 ]
```
### Buffer 

```csharp
using Encryption.Blowfish;
using System.Security.Cryptography;

var key = "a3bd614b27864e3f854b971f9df1a802"; // cipher key
var iv = RandomNumberGenerator.GetBytes(8); // IV
byte[] buf = ...; // data you want to encrypt
buf = buf.CopyAndPadIfNotAlreadyPadded();

var cbc = new BlowfishCbc(key);
var ok = cbc.Encrypt(buf, iv);
ok = cbc.Decrypt(buf, iv);
```

### Stream

```csharp
using Encryption.Blowfish;
using System.Security.Cryptography;

var codec = new Codec(Convert.FromHexString("df83d31539c244d298ce302036f91edd"));
var iv = RandomNumberGenerator.GetBytes(8);

// encrypt
using var encrypted = new MemoryStream();
using (var bfe = new BlowfishCtrEncryptStream(encrypted, codec, iv))
{
    bfe.Write(...);
    bfe.Write(...);
    // ...
}
// It is important to dispose or Close the stream as soon as the writing is finished.

enc.Position = 0;

// decrypt
using var decrypted = new MemoryStream();
using var bfd = new BlowfishCtrDecryptStream(encrypted, codec, iv);
bfd.CopyTo(decrypted);
```

## Available types

| type                       | mode       | usage                                                                                           | works on | thread-safe |
|:---------------------------|:-----------|:------------------------------------------------------------------------------------------------|:---------|:------------|
| *BlowfishEcb*              | [ECB][ecb] | Only when forced to. Lack of [diffusion][diff]. Require padded original data.                   | buffer   | yes         |
| *BlowfishCbc*              | [CBC][cbc] | Recommended. Require padded original data.                                                      | buffer   | yes         |
| *BlowfishCtr*              | [CTR][ctr] | Recommended. Works without padding.                                                             | buffer   | yes         |
| *ParallelBlowfishEcb*      | EBC        | Only when forced to. Parallel computation from certain data size. Require padded original data. | buffer   | yes         |
| *ParallelBlowfishCtr*      | CTR        | Recommended. Parallel computation from certain data size.  Works without padding.               | buffer   | yes         |
| *BlowfishCtrEncryptStream* | CTR        | Only when you need stream-sematics; otherwise you are better off with input buffer variants.    | stream   | no          |
| *BlowfishCtrDecryptStream* | CTR        | dtto                                                                                            | stream   | no          |

Some smaller ease-of-life extension methods are also available in the package.

## Development

see [development.md](development.md)


[bf]: https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html
[bfc]: https://www.schneier.com/wp-content/uploads/2015/12/constants-2.txt
[bftv]: https://www.schneier.com/wp-content/uploads/2015/12/vectors2-1.txt
[diff]: https://en.wikipedia.org/wiki/Confusion_and_diffusion#Diffusion
[ecb]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
[cbc]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
[ctr]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
