using System.Buffers.Binary;
using System.Numerics;

namespace FirmaDigital.Cripto.Propio;

/// <summary>
/// HashPropio-256: función hash diseñada para el laboratorio. Produce 256 bits (32 bytes).
///
/// Estado: 8 números de 32 bits (h0..h7) que arrancan con constantes fijas.
///
/// PASO 1 - Absorción: cada byte del mensaje entra al estado, uno por uno:
///     j     = i mod 8                       (a qué casilla le toca el byte i)
///     h[j]  = (h[j] XOR byte) * P           (P = 0x01000193, número primo; todo es mod 2^32)
///     h[j+1]= h[j+1] + RotarIzq(h[j], 5)    (el cambio "contagia" a la casilla vecina)
///   Al final se mezcla también la longitud del mensaje.
///
/// PASO 2 - Mezcla final: se guarda una copia del estado y se dan 4 vueltas en las que cada
///   casilla se combina con dos vecinas (suma, XOR, rotación, multiplicación y desplazamiento).
///   Por último se SUMA la copia guardada (realimentación). Esa suma es lo que hace
///   imposible deshacer el paso 2: para invertirlo habría que conocer el estado anterior,
///   que es justamente lo que se quiere averiguar.
///
/// Propiedades buscadas:
///   - Determinista: solo usa operaciones fijas, sin aleatoriedad.
///   - Irreversible: mensajes de cualquier tamaño se comprimen a 256 bits (se pierde información),
///     las multiplicaciones y XOR mezclan bits de forma no lineal y la realimentación final no se puede invertir.
///   - Efecto avalancha: cambiar un solo bit del mensaje cambia ~50 % de los bits del hash.
/// </summary>
public static class HashPropio
{
    public const string NombreAlgoritmo = "HashPropio-256";
    public const int TamanoSalida = 32;

    private const int VueltasMezcla = 4;
    private const uint PrimoAbsorcion = 0x01000193;       // primo de 32 bits
    private const uint MultiplicadorMezcla = 0x9E3779B1;  // ~ 2^32 / razón áurea (impar)

    // Constantes iniciales "sin trucos": parte fraccionaria de (raíz de p * pi) * 2^32,
    // para los primeros 8 primos. Solo se usan raíz y multiplicación (exactas en IEEE-754),
    // así que dan el mismo valor en cualquier computador.
    private static readonly uint[] EstadoInicial = GenerarConstantes([2, 3, 5, 7, 11, 13, 17, 19]);

    public static byte[] Calcular(ReadOnlySpan<byte> datos)
    {
        uint[] h = (uint[])EstadoInicial.Clone();

        // ---------------- PASO 1: absorción ----------------
        for (int i = 0; i < datos.Length; i++)
        {
            int j = i & 7;                                         // i mod 8
            h[j] = (h[j] ^ datos[i]) * PrimoAbsorcion;
            h[(j + 1) & 7] += BitOperations.RotateLeft(h[j], 5);
        }
        h[0] ^= (uint)datos.Length;

        // ---------------- PASO 2: mezcla final + realimentación ----------------
        uint[] copia = (uint[])h.Clone();
        for (int vuelta = 0; vuelta < VueltasMezcla; vuelta++)
        {
            for (int j = 0; j < 8; j++)
            {
                uint anterior = h[(j + 7) & 7];
                uint lejana = BitOperations.RotateLeft(h[(j + 3) & 7], 11);
                uint x = (h[j] + (anterior ^ lejana)) * MultiplicadorMezcla;
                h[j] = x ^ (x >> 16);
            }
        }
        for (int j = 0; j < 8; j++)
            h[j] += copia[j];

        byte[] salida = new byte[TamanoSalida];
        for (int j = 0; j < 8; j++)
            BinaryPrimitives.WriteUInt32BigEndian(salida.AsSpan(4 * j), h[j]);
        return salida;
    }

    private static uint[] GenerarConstantes(int[] primos)
    {
        var constantes = new uint[primos.Length];
        for (int i = 0; i < primos.Length; i++)
        {
            double x = Math.Sqrt(primos[i]) * Math.PI;
            constantes[i] = (uint)((x - Math.Floor(x)) * 4294967296.0);
        }
        return constantes;
    }
}
