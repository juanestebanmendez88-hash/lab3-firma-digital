namespace FirmaDigital.Red;

/// <summary>
/// Lo que viaja por TCP del emisor al receptor (se serializa como JSON).
/// </summary>
/// <param name="Mensaje">Texto original, sin cifrar.</param>
/// <param name="Firma">Hash del mensaje cifrado con la llave privada (Base64 en RSA, palabras de login.js en el propio).</param>
/// <param name="LlavePublica">Llave pública con la que el receptor descifra la firma.</param>
/// <param name="AlgoritmoHash">Nombre del algoritmo de hash usado.</param>
/// <param name="AlgoritmoCifrado">Nombre del algoritmo de llave privada/pública usado.</param>
public sealed record PaqueteFirmado(
    string Mensaje,
    string Firma,
    string LlavePublica,
    string AlgoritmoHash,
    string AlgoritmoCifrado);
