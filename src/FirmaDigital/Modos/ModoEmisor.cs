using System.Net.Sockets;
using FirmaDigital.Cripto;
using FirmaDigital.Cripto.Libreria;
using FirmaDigital.Cripto.Propio;
using FirmaDigital.Red;

namespace FirmaDigital.Modos;

/// <summary>Modo interactivo del emisor: el usuario escribe mensajes que se firman y se envían por TCP.</summary>
public static class ModoEmisor
{
    public static async Task EjecutarAsync(string? host, int? puerto)
    {
        Ui.Titulo("EMISOR: escribir, hashear, firmar y enviar por TCP");
        host ??= Ui.Preguntar("IP o nombre del receptor", "127.0.0.1");
        int puertoDestino = puerto ?? PreguntarEntero("Puerto del receptor", 5000);

        IHashAdapter hash = Ui.Preguntar("Hash        -> 1) SHA-256 (librería)   2) HashPropio-256 (propio)", "1") == "2"
            ? new HashPropioAdapter()
            : new Sha256Adapter();

        ICifradoAdapter cifrado = Ui.Preguntar("Llave priv. -> 1) RSA-2048 (librería)  2) CifradoPropio (propio)", "1") == "2"
            ? new CifradoPropioAdapter(PedirPalabraClave())
            : new RsaAdapter();

        try
        {
            var servicio = new ServicioFirma(hash, cifrado);
            Ui.LineaEmisor($"Algoritmos elegidos: {hash.Nombre} + {cifrado.Nombre}");
            Ui.LineaEmisor($"Huella de la llave pública: {ServicioFirma.Huella(hash, cifrado.LlavePublica)}");

            while (true)
            {
                string mensaje = Ui.Preguntar("\nMensaje a enviar (Enter vacío para volver al menú)");
                if (mensaje.Length == 0)
                    break;

                ResultadoFirma resultado = servicio.Firmar(mensaje);
                MostrarFirma(resultado);

                PaqueteFirmado paquete = resultado.Paquete;
                if (Ui.Preguntar("¿Simular que un atacante modifica el mensaje en el camino? (s/n)", "n")
                        .StartsWith("s", StringComparison.OrdinalIgnoreCase))
                {
                    string alterado = Ui.Preguntar("Texto que pondrá el atacante", mensaje + " (modificado)");
                    paquete = paquete with { Mensaje = alterado };
                }

                await EnviarYMostrarAsync(host, puertoDestino, paquete);
            }
        }
        finally
        {
            (cifrado as IDisposable)?.Dispose();
        }
    }

    public static void MostrarFirma(ResultadoFirma r)
    {
        Ui.LineaEmisor("Mensaje firmado:");
        Ui.Campo("Mensaje", r.Paquete.Mensaje);
        Ui.Campo("Algoritmos", $"{r.Paquete.AlgoritmoHash} + {r.Paquete.AlgoritmoCifrado}");
        Ui.Campo("1) Hash del mensaje", Ui.Hex(r.Hash));
        Ui.Campo("2) Firma (hash cifrado)", Ui.Hex(r.Firma));
        Ui.Campo("   Firma como se envía", Ui.Recortar(r.Paquete.Firma, 90));
        Ui.Campo("3) Llave pública enviada", Ui.Recortar(r.Paquete.LlavePublica, 90));
        Ui.Campo("Huella de la llave pública", r.HuellaLlavePublica);
    }

    public static async Task EnviarYMostrarAsync(string host, int puerto, PaqueteFirmado paquete)
    {
        Ui.LineaEmisor($"Enviando paquete por TCP a {host}:{puerto}...");
        try
        {
            string respuesta = await Emisor.EnviarAsync(host, puerto, paquete);
            Ui.LineaEmisor($"Respuesta del receptor: {respuesta}");
        }
        catch (SocketException ex)
        {
            Ui.Error($"[EMISOR]   No se pudo conectar con {host}:{puerto} ({ex.Message}). ¿Está corriendo el receptor?");
        }
    }

    public static int PreguntarEntero(string pregunta, int porDefecto)
    {
        while (true)
        {
            if (int.TryParse(Ui.Preguntar(pregunta, porDefecto.ToString()), out int valor) && valor is > 0 and < 65536)
                return valor;
            Ui.Error("Escriba un número de puerto válido (1-65535).");
        }
    }

    private static string PedirPalabraClave()
    {
        while (true)
        {
            string clave = Ui.Preguntar("Palabra clave (llave privada, ej. gato)");
            if (clave.Length > 0)
                return clave;
            Ui.Error("La palabra clave no puede estar vacía.");
        }
    }
}
