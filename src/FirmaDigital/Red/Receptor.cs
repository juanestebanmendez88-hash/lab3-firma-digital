using System.Net;
using System.Net.Sockets;
using FirmaDigital.Cripto;

namespace FirmaDigital.Red;

/// <summary>Servidor TCP: recibe paquetes firmados, verifica la firma y responde al emisor.</summary>
public static class Receptor
{
    public static async Task EjecutarAsync(int puerto, CancellationToken ct)
    {
        var escucha = new TcpListener(IPAddress.Any, puerto);
        escucha.Start();
        Ui.LineaReceptor($"Escuchando por TCP en el puerto {puerto}.");
        Ui.LineaReceptor($"IP de este equipo (para el emisor): {string.Join(", ", IpsLocales())}");
        Ui.LineaReceptor("Presione Ctrl+C para detener el receptor.");
        try
        {
            await AtenderAsync(escucha, ct);
        }
        finally
        {
            escucha.Stop();
        }
    }

    /// <summary>Atiende conexiones una por una hasta que se cancele.</summary>
    public static async Task AtenderAsync(TcpListener escucha, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient cliente;
            try
            {
                cliente = await escucha.AcceptTcpClientAsync(ct);
            }
            catch (Exception ex) when (ct.IsCancellationRequested &&
                                       ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                break;
            }

            using (cliente)
                await ProcesarAsync(cliente, ct);
        }
    }

    private static async Task ProcesarAsync(TcpClient cliente, CancellationToken ct)
    {
        try
        {
            NetworkStream flujo = cliente.GetStream();
            PaqueteFirmado paquete = Protocolo.Deserializar(await Protocolo.RecibirAsync(flujo, ct));

            Ui.LineaReceptor($"Paquete recibido desde {cliente.Client.RemoteEndPoint}:");
            Ui.Campo("Mensaje", paquete.Mensaje);
            Ui.Campo("Algoritmos", $"{paquete.AlgoritmoHash} + {paquete.AlgoritmoCifrado}");
            Ui.Campo("Firma recibida", Ui.Recortar(paquete.Firma, 90));
            Ui.Campo("Llave pública recibida", Ui.Recortar(paquete.LlavePublica, 90));

            ResultadoVerificacion r = ServicioFirma.Verificar(paquete);

            Ui.Campo("Huella de la llave pública", r.HuellaLlavePublica);
            Ui.Campo("Hash calculado del mensaje", Ui.Hex(r.HashCalculado));
            Ui.Campo("Hash descifrado de la firma", r.HashRecuperado is null ? "(no se pudo descifrar)" : Ui.Hex(r.HashRecuperado));
            if (r.Valida)
                Ui.Exito("[RECEPTOR] FIRMA VÁLIDA. " + r.Detalle);
            else
                Ui.Error("[RECEPTOR] FIRMA RECHAZADA. " + r.Detalle);

            string respuesta = r.Valida ? "FIRMA VÁLIDA: mensaje auténtico e íntegro." : "FIRMA RECHAZADA: " + r.Detalle;
            await Protocolo.EnviarAsync(flujo, respuesta, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Un paquete mal formado no debe tumbar el servidor; se informa y se sigue escuchando.
            Ui.Error($"[RECEPTOR] Error procesando la conexión: {ex.Message}");
        }
    }

    private static IEnumerable<string> IpsLocales()
    {
        try
        {
            return Dns.GetHostAddresses(Dns.GetHostName())
                .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
                .Select(ip => ip.ToString())
                .DefaultIfEmpty("127.0.0.1")
                .ToList();
        }
        catch (SocketException)
        {
            return ["127.0.0.1"];
        }
    }
}
