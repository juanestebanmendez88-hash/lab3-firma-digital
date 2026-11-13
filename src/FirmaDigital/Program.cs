using System.Text;
using FirmaDigital;
using FirmaDigital.Cripto.Libreria;
using FirmaDigital.Cripto.Propio;
using FirmaDigital.Modos;
using FirmaDigital.Red;

// Laboratorio: Firma Digital (versión consola).
//
// Uso sin argumentos: menú interactivo.
// Uso con argumentos:
//   receptor [puerto]          inicia el servidor TCP que verifica firmas (puerto por defecto 5000)
//   emisor [host] [puerto]     escribe, firma y envía mensajes
//   demo                       demostración automática (emisor + receptor + ataques)
//   pruebas                    pruebas de los algoritmos propios
//   hash <texto>               compara SHA-256 y HashPropio-256

try
{
    Console.OutputEncoding = Encoding.UTF8;
    Console.InputEncoding = Encoding.UTF8;
}
catch (IOException)
{
    // Algunas consolas no permiten cambiar la codificación; se sigue con la que tengan.
}

if (args.Length > 0)
{
    await EjecutarComandoAsync(args);
    return;
}

while (true)
{
    Ui.Titulo("LABORATORIO: FIRMA DIGITAL (versión consola)");
    Console.WriteLine("  1) Receptor  - escuchar y verificar mensajes firmados (servidor TCP)");
    Console.WriteLine("  2) Emisor    - escribir, hashear, firmar y enviar un mensaje (cliente TCP)");
    Console.WriteLine("  3) Demostración automática (emisor + receptor + ataques simulados)");
    Console.WriteLine("  4) Pruebas de los algoritmos propios");
    Console.WriteLine("  5) Calcular el hash de un texto (SHA-256 vs HashPropio-256)");
    Console.WriteLine("  0) Salir");

    string opcion = Ui.Preguntar("Opción");
    try
    {
        switch (opcion)
        {
            case "1": await EjecutarReceptorAsync(ModoEmisor.PreguntarEntero("Puerto", 5000)); break;
            case "2": await ModoEmisor.EjecutarAsync(null, null); break;
            case "3": await Demostracion.EjecutarAsync(); break;
            case "4": Pruebas.Ejecutar(); break;
            case "5": MostrarHashes(Ui.Preguntar("Texto")); break;
            case "0": return;
            default: Ui.Error("Opción no válida."); break;
        }
    }
    catch (Exception ex)
    {
        Ui.Error($"Error: {ex.Message}");
    }
}

static async Task EjecutarComandoAsync(string[] args)
{
    switch (args[0].ToLowerInvariant())
    {
        case "receptor":
            await EjecutarReceptorAsync(args.Length > 1 ? int.Parse(args[1]) : 5000);
            break;
        case "emisor":
            await ModoEmisor.EjecutarAsync(args.Length > 1 ? args[1] : null, args.Length > 2 ? int.Parse(args[2]) : null);
            break;
        case "demo":
            await Demostracion.EjecutarAsync();
            break;
        case "pruebas":
            Pruebas.Ejecutar();
            break;
        case "hash":
            MostrarHashes(string.Join(' ', args.Skip(1)));
            break;
        default:
            Ui.Error("Comando desconocido. Use: receptor [puerto] | emisor [host] [puerto] | demo | pruebas | hash <texto>");
            break;
    }
}

static async Task EjecutarReceptorAsync(int puerto)
{
    using var cts = new CancellationTokenSource();
    ConsoleCancelEventHandler alPresionarCtrlC = (_, e) =>
    {
        e.Cancel = true; // no cerrar el programa, solo detener el receptor
        cts.Cancel();
    };
    Console.CancelKeyPress += alPresionarCtrlC;
    try
    {
        await Receptor.EjecutarAsync(puerto, cts.Token);
    }
    finally
    {
        Console.CancelKeyPress -= alPresionarCtrlC;
    }
}

static void MostrarHashes(string texto)
{
    byte[] datos = Encoding.UTF8.GetBytes(texto);
    Ui.Info($"  Texto          : \"{texto}\"");
    Ui.Info($"  SHA-256        : {Ui.Hex(new Sha256Adapter().CalcularHash(datos))}");
    Ui.Info($"  HashPropio-256 : {Ui.Hex(new HashPropioAdapter().CalcularHash(datos))}");
}
