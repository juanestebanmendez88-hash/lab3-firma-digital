using System.Net.Sockets;

namespace FirmaDigital.Red;

/// <summary>Cliente TCP: se conecta al receptor, envía el paquete firmado y espera la respuesta.</summary>
public static class Emisor
{
    public static async Task<string> EnviarAsync(string host, int puerto, PaqueteFirmado paquete, CancellationToken ct = default)
    {
        using var cliente = new TcpClient();
        await cliente.ConnectAsync(host, puerto, ct);
        NetworkStream flujo = cliente.GetStream();

        await Protocolo.EnviarAsync(flujo, Protocolo.Serializar(paquete), ct);
        return await Protocolo.RecibirAsync(flujo, ct);
    }
}
