using System.Numerics;
using System.Security.Cryptography;

namespace FirmaDigital.Cripto.Libreria;

/// <summary>
/// Adaptador de la clase RSA de System.Security.Cryptography (Adaptee) a ICifradoAdapter (Target).
///
/// - Firmar: RSA.SignHash cifra el hash con la llave privada (s = m^d mod n, relleno PKCS#1 v1.5).
/// - Verificar: se "descifra" la firma con la llave pública (m = s^e mod n) usando BigInteger,
///   para poder mostrar explícitamente el hash recuperado, tal como en el esquema de firma digital.
/// </summary>
public sealed class RsaAdapter : ICifradoAdapter, IDisposable
{
    public const string NombreAlgoritmo = "RSA-2048";

    // DigestInfo de SHA-256 (RFC 8017, sección 9.2): identifica que el bloque contiene un hash de 256 bits.
    private static readonly byte[] PrefijoDigestInfo =
        [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

    private const int TamanoHash = 32;

    // El par de llaves se genera la primera vez que se necesita (el receptor nunca lo genera).
    private RSA? _rsa;
    private RSA Rsa => _rsa ??= RSA.Create(2048);

    public string Nombre => NombreAlgoritmo;

    public string LlavePublica => Convert.ToBase64String(Rsa.ExportSubjectPublicKeyInfo());

    public byte[] CifrarConLlavePrivada(byte[] hash)
    {
        if (hash.Length != TamanoHash)
            throw new ArgumentException("Este adaptador RSA firma hashes de 256 bits (32 bytes).", nameof(hash));

        return Rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public byte[] DescifrarConLlavePublica(byte[] firma, string llavePublica)
    {
        using RSA publica = RSA.Create();
        publica.ImportSubjectPublicKeyInfo(Convert.FromBase64String(llavePublica), out _);
        RSAParameters p = publica.ExportParameters(includePrivateParameters: false);

        byte[] modulo = p.Modulus!;
        var n = new BigInteger(modulo, isUnsigned: true, isBigEndian: true);
        var e = new BigInteger(p.Exponent!, isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(firma, isUnsigned: true, isBigEndian: true);

        if (firma.Length != modulo.Length || s >= n)
            throw new CryptographicException("La firma no tiene el tamaño de la llave pública.");

        // m = s^e mod n  ->  "descifrar con la llave pública"
        byte[] m = BigInteger.ModPow(s, e, n).ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] bloque = new byte[modulo.Length];
        m.CopyTo(bloque, bloque.Length - m.Length);

        // Formato esperado: 00 01 FF FF ... FF 00 || DigestInfo || hash
        int inicioDigest = bloque.Length - PrefijoDigestInfo.Length - TamanoHash;
        bool formatoValido = bloque[0] == 0x00 && bloque[1] == 0x01 && bloque[inicioDigest - 1] == 0x00;
        for (int i = 2; i < inicioDigest - 1; i++)
            formatoValido &= bloque[i] == 0xFF;
        formatoValido &= bloque.AsSpan(inicioDigest, PrefijoDigestInfo.Length).SequenceEqual(PrefijoDigestInfo);

        if (!formatoValido)
            throw new CryptographicException("el bloque descifrado no tiene formato PKCS#1, la firma no se creó con la llave privada de esta llave pública");

        return bloque[^TamanoHash..];
    }

    public string FirmaATexto(byte[] firma) => Convert.ToBase64String(firma);

    public byte[] TextoAFirma(string texto) => Convert.FromBase64String(texto);

    public void Dispose() => _rsa?.Dispose();
}
