namespace FirmaDigital;

/// <summary>Utilidades para mostrar información en la consola con colores.</summary>
internal static class Ui
{
    private static readonly Lock Cerrojo = new();

    public static void Titulo(string texto)
    {
        string linea = new('=', 78);
        Escribir(ConsoleColor.Cyan, $"\n{linea}\n  {texto}\n{linea}");
    }

    public static void Subtitulo(string texto) => Escribir(ConsoleColor.Yellow, $"\n--- {texto} ---");

    public static void LineaEmisor(string texto) => Escribir(ConsoleColor.Cyan, "[EMISOR]   " + texto);

    public static void LineaReceptor(string texto) => Escribir(ConsoleColor.Magenta, "[RECEPTOR] " + texto);

    public static void Campo(string etiqueta, string valor) => Escribir(ConsoleColor.Gray, $"           {etiqueta,-28}: {valor}");

    public static void Info(string texto) => Escribir(ConsoleColor.Gray, texto);

    public static void Exito(string texto) => Escribir(ConsoleColor.Green, texto);

    public static void Error(string texto) => Escribir(ConsoleColor.Red, texto);

    /// <summary>Bytes en hexadecimal; si son muchos, se muestran los primeros y el total.</summary>
    public static string Hex(byte[] datos, int maxBytes = 32) =>
        datos.Length <= maxBytes
            ? Convert.ToHexStringLower(datos)
            : $"{Convert.ToHexStringLower(datos, 0, maxBytes)}... ({datos.Length} bytes)";

    public static string Recortar(string texto, int max = 64) =>
        texto.Length <= max ? texto : $"{texto[..max]}... ({texto.Length} caracteres)";

    public static string Preguntar(string pregunta, string? porDefecto = null)
    {
        lock (Cerrojo)
            Console.Write(porDefecto is null ? $"{pregunta}: " : $"{pregunta} [{porDefecto}]: ");

        // Se quita el BOM (﻿) que algunas consolas agregan al inicio de la entrada.
        string respuesta = (Console.ReadLine() ?? "").Trim().TrimStart('﻿').Trim();
        return respuesta.Length == 0 ? porDefecto ?? "" : respuesta;
    }

    private static void Escribir(ConsoleColor color, string texto)
    {
        lock (Cerrojo)
        {
            ConsoleColor anterior = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(texto);
            Console.ForegroundColor = anterior;
        }
    }
}
