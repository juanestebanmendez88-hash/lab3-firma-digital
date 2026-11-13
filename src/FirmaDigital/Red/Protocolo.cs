using System.Buffers.Binary;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace FirmaDigital.Red;

/// <summary>
/// Protocolo sobre TCP: cada mensaje se envía como [4 bytes con la longitud][texto UTF-8].
/// TCP entrega un flujo continuo de bytes (no mensajes separados), por eso se antepone la longitud:
/// el receptor sabe exactamente cuántos bytes leer.
/// </summary>
public static class Protocolo
{
    private const int TamanoMaximo = 1 << 20; // 1 MiB

    private static readonly JsonSerializerOptions OpcionesJson = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping, // deja las tildes legibles
        RespectNullableAnnotations = true,                     // rechaza campos nulos
        RespectRequiredConstructorParameters = true,           // rechaza campos faltantes
    };

    public static string Serializar(PaqueteFirmado paquete) => JsonSerializer.Serialize(paquete, OpcionesJson);

    public static PaqueteFirmado Deserializar(string json) =>
        JsonSerializer.Deserialize<PaqueteFirmado>(json, OpcionesJson) ?? throw new JsonException("Paquete vacío.");

    public static async Task EnviarAsync(Stream flujo, string texto, CancellationToken ct = default)
    {
        byte[] cuerpo = Encoding.UTF8.GetBytes(texto);
        byte[] cabecera = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(cabecera, cuerpo.Length);
        await flujo.WriteAsync(cabecera, ct);
        await flujo.WriteAsync(cuerpo, ct);
        await flujo.FlushAsync(ct);
    }

    public static async Task<string> RecibirAsync(Stream flujo, CancellationToken ct = default)
    {
        byte[] cabecera = new byte[4];
        await flujo.ReadExactlyAsync(cabecera, ct);
        int largo = BinaryPrimitives.ReadInt32BigEndian(cabecera);
        if (largo < 0 || largo > TamanoMaximo)
            throw new InvalidDataException($"Tamaño de mensaje inválido: {largo} bytes.");

        byte[] cuerpo = new byte[largo];
        await flujo.ReadExactlyAsync(cuerpo, ct);
        return Encoding.UTF8.GetString(cuerpo);
    }
}
