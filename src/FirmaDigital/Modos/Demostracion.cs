using System.Net;
using System.Net.Sockets;
using FirmaDigital.Cripto;
using FirmaDigital.Cripto.Libreria;
using FirmaDigital.Cripto.Propio;
using FirmaDigital.Red;

namespace FirmaDigital.Modos;

/// <summary>
/// Corre emisor y receptor en el mismo programa (por TCP local) y muestra tres casos para
/// cada par de algoritmos: mensaje legítimo, mensaje alterado e impostor. Útil para las capturas del informe.
/// </summary>
public static class Demostracion
{
    private const string Local = "127.0.0.1";
    private const string MensajeOriginal = "Transferir $50.000 a la cuenta 123-456";
    private const string MensajeAlterado = "Transferir $9.000.000 a la cuenta 666-999";

    public static async Task EjecutarAsync()
    {
        using var cts = new CancellationTokenSource();
        var escucha = new TcpListener(IPAddress.Loopback, 0); // puerto 0 = el sistema elige uno libre
        escucha.Start();
        int puerto = ((IPEndPoint)escucha.LocalEndpoint).Port;
        Task servidor = Receptor.AtenderAsync(escucha, cts.Token);

        Ui.Titulo("DEMOSTRACIÓN AUTOMÁTICA DE FIRMA DIGITAL");
        Ui.Info($"Receptor local escuchando en {Local}:{puerto}. Emisor y receptor corren en este mismo programa.");

        try
        {
            using var rsa = new RsaAdapter();
            using var rsaImpostor = new RsaAdapter();

            await EscenariosAsync("PUNTO 1 - LIBRERÍAS DE C#: SHA-256 + RSA-2048",
                new Sha256Adapter(), rsa, rsaImpostor, puerto);

            await EscenariosAsync("PUNTO 2 - ALGORITMOS PROPIOS: HashPropio-256 + CifradoPropio (clave \"gato\")",
                new HashPropioAdapter(), new CifradoPropioAdapter("gato"), new CifradoPropioAdapter("perro"), puerto);

            Ui.Titulo("PATRÓN ADAPTADOR: COMBINACIÓN MIXTA HashPropio-256 + RSA-2048");
            Ui.Info("ServicioFirma no cambia en nada: solo recibe otros adaptadores.");
            ResultadoFirma mixto = new ServicioFirma(new HashPropioAdapter(), rsa).Firmar(MensajeOriginal);
            ModoEmisor.MostrarFirma(mixto);
            await ModoEmisor.EnviarYMostrarAsync(Local, puerto, mixto.Paquete);
        }
        finally
        {
            cts.Cancel();
            escucha.Stop();
            await servidor;
        }
    }

    private static async Task EscenariosAsync(
        string titulo, IHashAdapter hash, ICifradoAdapter cifrado, ICifradoAdapter impostor, int puerto)
    {
        Ui.Titulo(titulo);
        ResultadoFirma legitimo = new ServicioFirma(hash, cifrado).Firmar(MensajeOriginal);

        Ui.Subtitulo("Caso 1: mensaje legítimo (se espera FIRMA VÁLIDA)");
        ModoEmisor.MostrarFirma(legitimo);
        await ModoEmisor.EnviarYMostrarAsync(Local, puerto, legitimo.Paquete);

        Ui.Subtitulo("Caso 2: un atacante cambia el texto en el camino (falla la INTEGRIDAD)");
        Ui.LineaEmisor($"El atacante cambia el mensaje por \"{MensajeAlterado}\" y deja la firma original.");
        await ModoEmisor.EnviarYMostrarAsync(Local, puerto, legitimo.Paquete with { Mensaje = MensajeAlterado });

        Ui.Subtitulo("Caso 3: un impostor firma con SU llave privada y se hace pasar por el emisor (falla la AUTENTICIDAD)");
        ResultadoFirma falso = new ServicioFirma(hash, impostor).Firmar(MensajeAlterado);
        Ui.LineaEmisor("El impostor envía su mensaje y su firma, pero acompañados de la llave pública del emisor legítimo.");
        await ModoEmisor.EnviarYMostrarAsync(Local, puerto, falso.Paquete with { LlavePublica = legitimo.Paquete.LlavePublica });
    }
}
