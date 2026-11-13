using System.Security.Cryptography;
using System.Text;

namespace FirmaDigital.Cripto.Propio;

/// <summary>
/// Diccionario tomado de login.js (las mismas palabras). Se usa en dos lugares del algoritmo propio:
///
/// 1. Traducir(): es la misma función encrypt() de login.js. Pasa la palabra clave a minúsculas y
///    cambia cada letra o número por su palabra ("gato" -> "muchovidapenguinde"). Con eso se prepara
///    la llave privada antes de hashearla. Esta traducción NO es reversible (por ejemplo "y" y "j" dan
///    las dos "es"), pero aquí no hace falta revertirla: después va al hash, que tampoco se revierte.
///
/// 2. BytesAPalabras() / PalabrasABytes(): la firma y la llave pública viajan por la red escritas con
///    las palabras del diccionario. Cada byte se escribe en hexadecimal (0-9, a-f) y cada dígito se
///    cambia por su palabra (8 -> "fife", b -> "mucho", ...). Para esos 16 dígitos ninguna palabra se repite,
///    así que sí se puede volver de las palabras a los bytes. El 0 no estaba en login.js y se le asignó "uwu".
/// </summary>
public static class Diccionario
{
    public const string Separador = "-";

    /// <summary>Mismo contenido que <c>const dictionary</c> en login.js.</summary>
    public static readonly IReadOnlyDictionary<char, string> Palabras = new Dictionary<char, string>
    {
        ['q'] = "juanxd",
        ['w'] = "uwu",
        ['e'] = "xd2",
        ['r'] = "club",
        ['t'] = "penguin",
        ['y'] = "es",
        ['u'] = "lo",
        ['i'] = "mejor",
        ['o'] = "de",
        ['p'] = "la",
        ['a'] = "vida",
        ['s'] = "me",
        ['d'] = "encanta",
        ['f'] = "XD",
        ['g'] = "mucho",
        ['h'] = "aleja",
        ['j'] = "es",
        ['k'] = "la",
        ['l'] = "mejor",
        ['z'] = "y",
        ['x'] = "juan",
        ['c'] = "tmb",
        ['v'] = "quiero",
        ['b'] = "mucho",
        ['n'] = "a",
        ['m'] = "mis",
        ['1'] = "amigues",
        ['2'] = "pongan",
        ['3'] = "bachata",
        ['4'] = "memotenpiedad",
        ['5'] = "tilin",
        ['6'] = "puffle",
        ['7'] = "pinguino",
        ['8'] = "fife",
        ['9'] = "elbicho",
    };

    // Palabras para los 16 dígitos hexadecimales (el 0 no existe en login.js, se le asigna "uwu").
    private static readonly Dictionary<char, string> PalabraDeDigito =
        "0123456789abcdef".ToDictionary(digito => digito, digito => digito == '0' ? "uwu" : Palabras[digito]);

    // Tabla inversa. ToDictionary falla si dos dígitos tuvieran la misma palabra, lo que garantiza
    // desde el arranque que la conversión es reversible.
    private static readonly Dictionary<string, char> DigitoDePalabra =
        PalabraDeDigito.ToDictionary(par => par.Value, par => par.Key);

    /// <summary>Equivalente en C# de la función encrypt() de login.js.</summary>
    public static string Traducir(string texto)
    {
        // 1. Pasar todo a minúsculas
        string minusculas = texto.ToLowerInvariant();

        // 2-4. Recorrer cada caracter y acumular el resultado
        var resultado = new StringBuilder();
        foreach (char caracter in minusculas)
        {
            // 5. Si el caracter está en el diccionario se reemplaza; si no, se deja igual
            if (Palabras.TryGetValue(caracter, out string? palabra))
                resultado.Append(palabra);
            else
                resultado.Append(caracter);
        }
        return resultado.ToString();
    }

    /// <summary>Bytes -> hexadecimal -> palabras del diccionario separadas por guiones.</summary>
    public static string BytesAPalabras(byte[] datos) =>
        string.Join(Separador, Convert.ToHexStringLower(datos).Select(digito => PalabraDeDigito[digito]));

    /// <summary>Palabras del diccionario -> hexadecimal -> bytes (operación inversa).</summary>
    public static byte[] PalabrasABytes(string texto)
    {
        if (texto.Length == 0)
            return [];

        var hex = new StringBuilder();
        foreach (string palabra in texto.Split(Separador))
        {
            if (!DigitoDePalabra.TryGetValue(palabra, out char digito))
                throw new CryptographicException($"la palabra \"{palabra}\" no está en el diccionario");
            hex.Append(digito);
        }

        if (hex.Length % 2 != 0)
            throw new CryptographicException("el texto no tiene un número par de dígitos");
        return Convert.FromHexString(hex.ToString());
    }
}
