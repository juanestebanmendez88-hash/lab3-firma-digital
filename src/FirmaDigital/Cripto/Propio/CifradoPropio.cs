using System.Security.Cryptography;
using System.Text;

namespace FirmaDigital.Cripto.Propio;

/// <summary>
/// CifradoPropio: algoritmo de llave privada diseñado para el laboratorio. Solo tiene 2 pasos.
///
/// LLAVES
///   - Llave privada: una palabra clave elegida por el usuario (ej. "gato"). Nunca se envía.
///   - Llave pública: K = HashPropio(Diccionario.Traducir(palabra clave)) -> 32 bytes.
///     Primero la palabra pasa por el diccionario de login.js ("gato" -> "muchovidapenguinde")
///     y luego por el hash propio. K se envía junto al mensaje escrita con las palabras del
///     diccionario. Con K se puede revertir el cifrado, pero NO se puede obtener la palabra
///     clave, porque el hash es irreversible.
///
/// CIFRAR (m = bytes a cifrar, L = cantidad de bytes, K[i] = byte i de la llave, repetido cada 32,
///         ROTL3 = rotar el byte 3 bits a la izquierda, todas las sumas mod 256)
///   Paso 1 - Sustitución encadenada de ida y vuelta:
///       ida:    a[i] = ROTL3((m[i] XOR K[i]) + a[i-1]),   con a[-1] = K[31]   (i = 0 .. L-1)
///       vuelta: c[i] = ROTL3(a[i] + c[i+1]),              con c[L]  = K[0]    (i = L-1 .. 0)
///     El XOR oculta cada byte con la llave. La suma con el byte vecino encadena los bytes:
///     en la ida un cambio arrastra a los bytes siguientes y en la vuelta, a los anteriores,
///     así que alcanza a todos. La rotación mezcla los bits altos con los bajos para que la
///     diferencia no viaje igual de byte en byte (sin ella la difusión se queda en 11 %).
///   Paso 2 - Transposición por saltos:
///       el byte de la posición i pasa a la posición (i * salto + inicio) mod L
///     salto e inicio salen de la llave (salto es coprimo con L para que ninguna posición se repita).
///
/// DESCIFRAR (con la llave pública K): se hacen los pasos al revés (ROTR3 = rotar a la derecha).
///   Paso 2 inverso: c[i] = cifrado[(i * salto + inicio) mod L]
///   Vuelta inversa: a[i] = ROTR3(c[i]) - c[i+1]
///   Ida inversa:    m[i] = (ROTR3(a[i]) - a[i-1]) XOR K[i]
/// </summary>
public static class CifradoPropio
{
    public const string NombreAlgoritmo = "CifradoPropio";
    public const int TamanoLlave = HashPropio.TamanoSalida; // 32 bytes
    private const int Rotacion = 3;

    /// <summary>Resultado intermedio, útil para explicar el algoritmo paso a paso.</summary>
    public sealed record Traza(byte[] Entrada, byte[] Ida, byte[] DespuesPaso1, byte[] DespuesPaso2, int Salto, int Inicio);

    /// <summary>
    /// Convierte la palabra clave (llave privada) en la llave pública K de 32 bytes:
    /// palabra -> diccionario de login.js -> HashPropio.
    /// </summary>
    public static byte[] DerivarLlavePublica(string palabraClave)
    {
        if (string.IsNullOrEmpty(palabraClave))
            throw new ArgumentException("La palabra clave no puede estar vacía.", nameof(palabraClave));
        string traducida = Diccionario.Traducir(palabraClave);
        return HashPropio.Calcular(Encoding.UTF8.GetBytes(traducida));
    }

    public static byte[] Cifrar(byte[] mensaje, byte[] llave) => CifrarConTraza(mensaje, llave).DespuesPaso2;

    public static Traza CifrarConTraza(byte[] mensaje, byte[] llave)
    {
        ValidarLlave(llave);
        int largo = mensaje.Length;

        // Paso 1, ida: XOR con la llave, suma con el byte anterior y rotación
        byte[] ida = new byte[largo];
        byte anterior = llave[TamanoLlave - 1];
        for (int i = 0; i < largo; i++)
        {
            ida[i] = Rotl((byte)((mensaje[i] ^ llave[i % TamanoLlave]) + anterior));
            anterior = ida[i];
        }

        // Paso 1, vuelta: suma con el byte siguiente y rotación, de atrás hacia adelante
        byte[] paso1 = new byte[largo];
        byte siguiente = llave[0];
        for (int i = largo - 1; i >= 0; i--)
        {
            paso1[i] = Rotl((byte)(ida[i] + siguiente));
            siguiente = paso1[i];
        }

        // Paso 2: transposición por saltos
        (int salto, int inicio) = ParametrosTransposicion(llave, largo);
        byte[] paso2 = new byte[largo];
        for (int i = 0; i < largo; i++)
            paso2[(i * salto + inicio) % largo] = paso1[i];

        return new Traza(mensaje, ida, paso1, paso2, salto, inicio);
    }

    public static byte[] Descifrar(byte[] cifrado, byte[] llave)
    {
        ValidarLlave(llave);
        int largo = cifrado.Length;

        // Paso 2 inverso: devolver cada byte a su posición original
        (int salto, int inicio) = ParametrosTransposicion(llave, largo);
        byte[] paso1 = new byte[largo];
        for (int i = 0; i < largo; i++)
            paso1[i] = cifrado[(i * salto + inicio) % largo];

        // Vuelta inversa: deshacer la rotación y restar el byte siguiente (ya cifrado)
        byte[] ida = new byte[largo];
        for (int i = 0; i < largo; i++)
        {
            byte siguiente = i + 1 < largo ? paso1[i + 1] : llave[0];
            ida[i] = (byte)(Rotr(paso1[i]) - siguiente);
        }

        // Ida inversa: deshacer la rotación, restar el byte anterior y quitar el XOR
        byte[] mensaje = new byte[largo];
        byte anterior = llave[TamanoLlave - 1];
        for (int i = 0; i < largo; i++)
        {
            mensaje[i] = (byte)((byte)(Rotr(ida[i]) - anterior) ^ llave[i % TamanoLlave]);
            anterior = ida[i];
        }
        return mensaje;
    }

    private static byte Rotl(byte x) => (byte)((x << Rotacion) | (x >> (8 - Rotacion)));

    private static byte Rotr(byte x) => (byte)((x >> Rotacion) | (x << (8 - Rotacion)));

    /// <summary>La llave pública viaja escrita con las palabras del diccionario de login.js.</summary>
    public static string ExportarLlave(byte[] llave) => Diccionario.BytesAPalabras(llave);

    public static byte[] ImportarLlave(string texto)
    {
        byte[] llave = Diccionario.PalabrasABytes(texto);
        ValidarLlave(llave);
        return llave;
    }

    /// <summary>
    /// salto: número entre 2 y L-1 que no comparte divisores con L (así la transposición es una
    /// permutación: cada byte cae en una posición distinta). inicio: desplazamiento entre 0 y L-1.
    /// </summary>
    private static (int Salto, int Inicio) ParametrosTransposicion(byte[] llave, int largo)
    {
        if (largo <= 2)
            return (1, largo == 0 ? 0 : llave[1] % largo);

        int salto = 2 + llave[0] % (largo - 2);
        while (Mcd(salto, largo) != 1)
            salto++;               // como mucho llega a L-1, que siempre es coprimo con L
        return (salto, llave[1] % largo);
    }

    private static int Mcd(int a, int b)
    {
        while (b != 0)
            (a, b) = (b, a % b);
        return a;
    }

    private static void ValidarLlave(byte[] llave)
    {
        if (llave.Length != TamanoLlave)
            throw new CryptographicException($"La llave debe tener {TamanoLlave} bytes.");
    }
}
