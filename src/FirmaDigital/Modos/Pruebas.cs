using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using FirmaDigital.Cripto;
using FirmaDigital.Cripto.Libreria;
using FirmaDigital.Cripto.Propio;

namespace FirmaDigital.Modos;

/// <summary>
/// Pruebas que sirven como evidencia para el informe: determinismo, avalancha, distribución
/// y colisiones del hash propio; reversibilidad y sensibilidad a la clave del cifrado propio.
/// Usan semillas fijas, así que dan los mismos números en cada ejecución.
/// </summary>
public static class Pruebas
{
    private const int Muestras = 10_000;

    public static void Ejecutar()
    {
        var propio = new HashPropioAdapter();
        var sha256 = new Sha256Adapter();

        Ui.Titulo("PRUEBAS DEL HASH PROPIO (HashPropio-256)");
        Determinismo(propio);
        AvalanchaEjemplo(propio);
        Ui.Subtitulo($"Hash 3. Efecto avalancha: {Muestras:N0} mensajes aleatorios, se cambia 1 bit (ideal: 128 de 256 bits = 50 %)");
        AvalanchaHash(propio);
        AvalanchaHash(sha256);
        Distribucion(propio);
        Colisiones(propio);
        TamanoFijo(propio);

        Ui.Titulo("PRUEBAS DEL CIFRADO PROPIO (CifradoPropio)");
        DiccionarioLoginJs();
        EjemploPasoAPaso();
        Reversibilidad();
        ClaveIncorrecta();
        SensibilidadClave();
        AvalanchaCifrado();
        ComparacionDisenos();

        Ui.Titulo("PRUEBA DEL ADAPTADOR RSA");
        RsaManualVsLibreria();
    }

    // ------------------------------------------------------------------ HASH

    private static void Determinismo(IHashAdapter hash)
    {
        Ui.Subtitulo("Hash 1. Determinismo: el mismo mensaje siempre produce el mismo hash");
        byte[] datos = Encoding.UTF8.GetBytes("Servicios Multimedia");
        string[] resultados = Enumerable.Range(0, 3).Select(_ => Ui.Hex(hash.CalcularHash(datos))).ToArray();
        foreach (string r in resultados)
            Ui.Info($"  \"Servicios Multimedia\" -> {r}");
        Resultado("Las 3 ejecuciones dan el mismo hash", resultados.Distinct().Count() == 1);
    }

    private static void AvalanchaEjemplo(IHashAdapter hash)
    {
        Ui.Subtitulo("Hash 2. Efecto avalancha con un ejemplo ('o' = 01101111 y 'n' = 01101110 difieren en 1 bit)");
        byte[] a = hash.CalcularHash(Encoding.UTF8.GetBytes("Hola mundo"));
        byte[] b = hash.CalcularHash(Encoding.UTF8.GetBytes("Hola mundn"));
        int bits = BitsDiferentes(a, b);
        Ui.Info($"  \"Hola mundo\" -> {Ui.Hex(a)}");
        Ui.Info($"  \"Hola mundn\" -> {Ui.Hex(b)}");
        Ui.Info($"  Bits distintos: {bits} de 256 ({bits / 256.0:P1})");
    }

    private static void AvalanchaHash(IHashAdapter hash)
    {
        var rnd = new Random(2026);
        long suma = 0;
        int minimo = int.MaxValue, maximo = 0;
        for (int n = 0; n < Muestras; n++)
        {
            byte[] mensaje = new byte[rnd.Next(1, 65)];
            rnd.NextBytes(mensaje);
            byte[] h1 = hash.CalcularHash(mensaje);
            CambiarBitAleatorio(mensaje, rnd);
            int d = BitsDiferentes(h1, hash.CalcularHash(mensaje));
            suma += d;
            minimo = Math.Min(minimo, d);
            maximo = Math.Max(maximo, d);
        }
        double promedio = (double)suma / Muestras;
        Ui.Info($"  {hash.Nombre,-15} promedio {promedio,6:F2} bits cambiados ({promedio / 256:P2})   mínimo {minimo}   máximo {maximo}");
    }

    private static void Distribucion(IHashAdapter hash)
    {
        Ui.Subtitulo($"Hash 4. Distribución de bits en {Muestras:N0} hashes (cada posición debería valer 1 la mitad de las veces)");
        var rnd = new Random(7);
        int[] unos = new int[256];
        for (int n = 0; n < Muestras; n++)
        {
            byte[] mensaje = new byte[rnd.Next(1, 65)];
            rnd.NextBytes(mensaje);
            byte[] h = hash.CalcularHash(mensaje);
            for (int bit = 0; bit < 256; bit++)
                unos[bit] += (h[bit / 8] >> (bit % 8)) & 1;
        }
        double total = unos.Sum() / (256.0 * Muestras);
        double min = unos.Min() / (double)Muestras, max = unos.Max() / (double)Muestras;
        Ui.Info($"  Proporción global de unos: {total:P2}   posición más baja: {min:P2}   posición más alta: {max:P2}");
        Resultado("Todas las posiciones entre 47 % y 53 %", min > 0.47 && max < 0.53);
    }

    private static void Colisiones(IHashAdapter hash)
    {
        const int cantidad = 200_000;
        Ui.Subtitulo($"Hash 5. Búsqueda de colisiones en {cantidad:N0} mensajes parecidos (\"mensaje 0\", \"mensaje 1\", ...)");
        var reloj = Stopwatch.StartNew();
        var vistos = new HashSet<string>();
        int colisiones = 0;
        for (int i = 0; i < cantidad; i++)
            if (!vistos.Add(Convert.ToHexString(hash.CalcularHash(Encoding.UTF8.GetBytes($"mensaje {i}")))))
                colisiones++;
        Ui.Info($"  Colisiones encontradas: {colisiones}   (tiempo: {reloj.ElapsedMilliseconds} ms)");
        Resultado("Ninguna colisión", colisiones == 0);
    }

    private static void TamanoFijo(IHashAdapter hash)
    {
        Ui.Subtitulo("Hash 6. Compresión: mensajes de cualquier tamaño producen 256 bits");
        foreach (int largo in new[] { 0, 1, 100, 1_000_000 })
        {
            byte[] h = hash.CalcularHash(new byte[largo]);
            Ui.Info($"  Mensaje de {largo,9:N0} bytes -> {h.Length * 8} bits: {Ui.Hex(h, 12)}");
        }
        Ui.Info("  Como infinitos mensajes caen en 2^256 resultados posibles, se pierde información: no hay forma de reconstruir el mensaje.");
    }

    // --------------------------------------------------------------- CIFRADO

    private static void DiccionarioLoginJs()
    {
        Ui.Subtitulo("Cifrado 0. Diccionario de login.js dentro del algoritmo");
        string traducida = Diccionario.Traducir("gato");
        byte[] llave = CifradoPropio.DerivarLlavePublica("gato");
        string enPalabras = CifradoPropio.ExportarLlave(llave);
        Ui.Info("  a) Preparación de la llave privada con encrypt() de login.js:");
        Ui.Info($"     \"gato\" -> g=mucho, a=vida, t=penguin, o=de -> \"{traducida}\"");
        Ui.Info($"     K = HashPropio(\"{traducida}\") = {Ui.Hex(llave)}");
        Ui.Info("  b) Cada dígito hexadecimal se escribe con su palabra para enviarlo:");
        Ui.Info($"     {Ui.Hex(llave, 4)} -> {Ui.Recortar(enPalabras, 70)}");
        Resultado("De las palabras se recuperan exactamente los mismos bytes",
            CifradoPropio.ImportarLlave(enPalabras).SequenceEqual(llave));

        Ui.Info("  Observación: el diccionario de login.js repite palabras (y/j = \"es\", p/k = \"la\", i/l = \"mejor\", g/b = \"mucho\").");
        Ui.Info($"     \"ya\" -> \"{Diccionario.Traducir("ya")}\"   y   \"ja\" -> \"{Diccionario.Traducir("ja")}\": dan la misma llave.");
        Ui.Info("     Por eso login.js no sirve como cifrado reversible, pero sí para preparar la llave, que de todas formas pasa por un hash.");
    }

    private static void EjemploPasoAPaso()
    {
        Ui.Subtitulo("Cifrado 1. Ejemplo paso a paso: cifrar \"Hola\" con la palabra clave \"gato\"");
        byte[] llave = CifradoPropio.DerivarLlavePublica("gato");
        byte[] mensaje = Encoding.UTF8.GetBytes("Hola");
        CifradoPropio.Traza t = CifradoPropio.CifrarConTraza(mensaje, llave);

        int largo = mensaje.Length;
        Ui.Info($"  Llave pública K = HashPropio(Traducir(\"gato\")) = {Ui.Hex(llave)}");
        Ui.Info($"  Valores iniciales: a[-1] = K[31] = {llave[^1]}   c[{largo}] = K[0] = {llave[0]}");
        Ui.Info("");
        Ui.Info("  PASO 1, ida: a[i] = ROTL3((m[i] XOR K[i]) + a[i-1])  (mod 256)");
        Ui.Info("   i | letra | m[i] | K[i] | m XOR K | + a[i-1] | suma | ROTL3 = a[i]");
        byte anterior = llave[^1];
        for (int i = 0; i < largo; i++)
        {
            int xor = mensaje[i] ^ llave[i];
            int suma = (xor + anterior) % 256;
            Ui.Info($"   {i} |   {(char)mensaje[i]}   | {mensaje[i],4} | {llave[i],4} | {xor,7} | {anterior,8} | {suma,4} | {t.Ida[i],12}");
            anterior = t.Ida[i];
        }
        Ui.Info("");
        Ui.Info("  PASO 1, vuelta (de atrás hacia adelante): c[i] = ROTL3(a[i] + c[i+1])  (mod 256)");
        Ui.Info("   i | a[i] | + c[i+1] | suma | ROTL3 = c[i]");
        byte siguiente = llave[0];
        for (int i = largo - 1; i >= 0; i--)
        {
            int suma = (t.Ida[i] + siguiente) % 256;
            Ui.Info($"   {i} | {t.Ida[i],4} | {siguiente,8} | {suma,4} | {t.DespuesPaso1[i],12}");
            siguiente = t.DespuesPaso1[i];
        }
        Ui.Info("");
        Ui.Info($"  PASO 2: el byte i se mueve a la posición (i * {t.Salto} + {t.Inicio}) mod {largo}");
        for (int i = 0; i < largo; i++)
            Ui.Info($"   c[{i}] = {t.DespuesPaso1[i],3} -> posición {(i * t.Salto + t.Inicio) % largo}");
        Ui.Info("");
        Ui.Info($"  Resultado cifrado: [{string.Join(", ", t.DespuesPaso2)}]");
        byte[] descifrado = CifradoPropio.Descifrar(t.DespuesPaso2, llave);
        Ui.Info($"  Descifrado con K : [{string.Join(", ", descifrado)}] = \"{Encoding.UTF8.GetString(descifrado)}\"");
        Resultado("El descifrado devuelve el mensaje original", descifrado.SequenceEqual(mensaje));
    }

    private static void Reversibilidad()
    {
        Ui.Subtitulo($"Cifrado 2. Reversibilidad: {Muestras:N0} mensajes y claves aleatorias");
        var rnd = new Random(11);
        int correctos = 0;
        for (int n = 0; n < Muestras; n++)
        {
            byte[] llave = CifradoPropio.DerivarLlavePublica(ClaveAleatoria(rnd));
            byte[] mensaje = new byte[rnd.Next(1, 100)];
            rnd.NextBytes(mensaje);
            // Se exporta e importa la llave como texto, igual que cuando viaja por la red.
            byte[] llaveRecibida = CifradoPropio.ImportarLlave(CifradoPropio.ExportarLlave(llave));
            if (CifradoPropio.Descifrar(CifradoPropio.Cifrar(mensaje, llave), llaveRecibida).SequenceEqual(mensaje))
                correctos++;
        }
        Ui.Info($"  Descifrados correctamente: {correctos:N0} de {Muestras:N0}");
        Resultado("Descifrar(Cifrar(m)) = m en todos los casos", correctos == Muestras);
    }

    private static void ClaveIncorrecta()
    {
        Ui.Subtitulo("Cifrado 3. Con una llave pública que no corresponde no se recupera el mensaje");
        byte[] hash = HashPropio.Calcular(Encoding.UTF8.GetBytes("Hola mundo"));
        byte[] firma = CifradoPropio.Cifrar(hash, CifradoPropio.DerivarLlavePublica("gato"));
        byte[] conOtraLlave = CifradoPropio.Descifrar(firma, CifradoPropio.DerivarLlavePublica("perro"));
        Ui.Info($"  Hash original              : {Ui.Hex(hash)}");
        Ui.Info($"  Firmado con \"gato\"         : {Ui.Hex(firma)}");
        Ui.Info($"  Descifrado con K de \"perro\": {Ui.Hex(conOtraLlave)}");
        Resultado("El resultado no coincide con el hash original", !conOtraLlave.SequenceEqual(hash));
    }

    private static void SensibilidadClave()
    {
        Ui.Subtitulo("Cifrado 4. Sensibilidad a la clave: \"gato\" vs \"gatp\" (una letra de diferencia)");
        byte[] k1 = CifradoPropio.DerivarLlavePublica("gato");
        byte[] k2 = CifradoPropio.DerivarLlavePublica("gatp");
        byte[] hash = HashPropio.Calcular(Encoding.UTF8.GetBytes("Hola mundo"));
        byte[] c1 = CifradoPropio.Cifrar(hash, k1);
        byte[] c2 = CifradoPropio.Cifrar(hash, k2);
        Ui.Info($"  K(\"gato\") = {Ui.Hex(k1)}");
        Ui.Info($"  K(\"gatp\") = {Ui.Hex(k2)}");
        Ui.Info($"  Bits distintos entre las llaves públicas: {BitsDiferentes(k1, k2)} de 256");
        Ui.Info($"  Bits distintos entre las firmas         : {BitsDiferentes(c1, c2)} de 256");
        Ui.Info("  La llave pública es el hash de la palabra clave traducida: no se parece a ella y no permite recuperarla.");
    }

    private static void AvalanchaCifrado()
    {
        Ui.Subtitulo($"Cifrado 5. Difusión: {Muestras:N0} bloques de 32 bytes, se cambia 1 bit del mensaje");
        var rnd = new Random(5);
        byte[] llave = CifradoPropio.DerivarLlavePublica("gato");
        long suma = 0;
        for (int n = 0; n < Muestras; n++)
        {
            byte[] mensaje = new byte[32];
            rnd.NextBytes(mensaje);
            byte[] c1 = CifradoPropio.Cifrar(mensaje, llave);
            CambiarBitAleatorio(mensaje, rnd);
            suma += BitsDiferentes(c1, CifradoPropio.Cifrar(mensaje, llave));
        }
        double promedio = (double)suma / Muestras;
        Ui.Info($"  Promedio de bits cambiados en el cifrado: {promedio:F2} de 256 ({promedio / 256:P2})");
        Ui.Info("  La ida lleva el cambio a los bytes siguientes, la vuelta a los anteriores y la rotación lo mezcla entre bits.");
        Resultado("Difusión entre 45 % y 55 % (ideal: 50 %)", promedio / 256 is > 0.45 and < 0.55);
    }

    /// <summary>
    /// Justifica el diseño del paso 1: mide la difusión de las variantes que se probaron con los mismos
    /// datos. La transposición del paso 2 solo mueve bytes, así que no cambia la cantidad de bits distintos.
    /// </summary>
    private static void ComparacionDisenos()
    {
        Ui.Subtitulo($"Cifrado 6. Justificación del paso 1: difusión de cada variante ({Muestras:N0} bloques, 1 bit cambiado)");
        var variantes = new (string Nombre, Func<byte[], byte[], byte[]> Paso1)[]
        {
            ("Solo ida, sin rotación (diseño inicial)", (m, k) => Paso1Variante(m, k, vuelta: false, rotar: false)),
            ("Ida y vuelta, sin rotación", (m, k) => Paso1Variante(m, k, vuelta: true, rotar: false)),
            ("Ida y vuelta con rotación (CifradoPropio)", (m, k) => CifradoPropio.CifrarConTraza(m, k).DespuesPaso1),
        };
        byte[] llave = CifradoPropio.DerivarLlavePublica("gato");
        foreach (var (nombre, paso1) in variantes)
        {
            var rnd = new Random(5);
            long suma = 0;
            for (int n = 0; n < Muestras; n++)
            {
                byte[] mensaje = new byte[32];
                rnd.NextBytes(mensaje);
                byte[] c1 = paso1(mensaje, llave);
                CambiarBitAleatorio(mensaje, rnd);
                suma += BitsDiferentes(c1, paso1(mensaje, llave));
            }
            double promedio = (double)suma / Muestras;
            Ui.Info($"  {nombre,-42} {promedio,6:F2} de 256 bits ({promedio / 256:P2})");
        }
        Ui.Info("  Con solo sumas, la diferencia viaja como el mismo desplazamiento de byte en byte; la rotación la mezcla.");
    }

    private static byte[] Paso1Variante(byte[] m, byte[] k, bool vuelta, bool rotar)
    {
        byte Rotar(byte x) => rotar ? (byte)((x << 3) | (x >> 5)) : x;
        var ida = new byte[m.Length];
        byte anterior = k[31];
        for (int i = 0; i < m.Length; i++)
            anterior = ida[i] = Rotar((byte)((m[i] ^ k[i % 32]) + anterior));
        if (!vuelta)
            return ida;
        var c = new byte[m.Length];
        byte siguiente = k[0];
        for (int i = m.Length - 1; i >= 0; i--)
            siguiente = c[i] = Rotar((byte)(ida[i] + siguiente));
        return c;
    }

    // ------------------------------------------------------------------ RSA

    private static void RsaManualVsLibreria()
    {
        Ui.Subtitulo("Descifrar la firma con la llave pública (BigInteger) vs RSA.VerifyHash de la librería");
        using RSA rsa = RSA.Create(2048);
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("Hola mundo"));
        byte[] firma = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        bool libreria = rsa.VerifyHash(hash, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var adaptador = new RsaAdapter();
        byte[] recuperado = adaptador.DescifrarConLlavePublica(firma, Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()));
        Ui.Info($"  Hash SHA-256 original         : {Ui.Hex(hash)}");
        Ui.Info($"  Hash recuperado de la firma   : {Ui.Hex(recuperado)}");
        Resultado("RSA.VerifyHash (librería) acepta la firma", libreria);
        Resultado("El hash recuperado manualmente es igual al original", recuperado.SequenceEqual(hash));
    }

    // ------------------------------------------------------------- utilidades

    private static int BitsDiferentes(byte[] a, byte[] b)
    {
        int bits = 0;
        for (int i = 0; i < a.Length; i++)
            bits += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return bits;
    }

    private static void CambiarBitAleatorio(byte[] datos, Random rnd)
    {
        int bit = rnd.Next(datos.Length * 8);
        datos[bit / 8] ^= (byte)(1 << (bit % 8));
    }

    private static string ClaveAleatoria(Random rnd)
    {
        const string letras = "abcdefghijklmnopqrstuvwxyz";
        return new string(Enumerable.Range(0, rnd.Next(3, 13)).Select(_ => letras[rnd.Next(letras.Length)]).ToArray());
    }

    private static void Resultado(string descripcion, bool correcto)
    {
        if (correcto)
            Ui.Exito($"  [OK]    {descripcion}");
        else
            Ui.Error($"  [FALLA] {descripcion}");
    }
}
