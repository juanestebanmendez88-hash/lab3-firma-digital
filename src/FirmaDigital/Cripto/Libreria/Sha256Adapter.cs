using System.Security.Cryptography;

namespace FirmaDigital.Cripto.Libreria;

/// <summary>
/// Adaptador de la clase SHA256 de System.Security.Cryptography (adaptado / Adaptee)
/// a la interfaz IHashAdapter (objetivo / Target).
/// </summary>
public sealed class Sha256Adapter : IHashAdapter
{
    public const string NombreAlgoritmo = "SHA-256";

    public string Nombre => NombreAlgoritmo;

    public byte[] CalcularHash(byte[] datos) => SHA256.HashData(datos);
}
