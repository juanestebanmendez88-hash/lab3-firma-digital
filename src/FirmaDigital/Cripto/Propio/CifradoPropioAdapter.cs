namespace FirmaDigital.Cripto.Propio;

/// <summary>
/// Adaptador del algoritmo propio CifradoPropio (Adaptee) a ICifradoAdapter (Target).
/// CifradoPropio trabaja con una llave de 32 bytes; este adaptador la obtiene a partir
/// de la palabra clave y la convierte a texto para enviarla por la red.
/// </summary>
public sealed class CifradoPropioAdapter : ICifradoAdapter
{
    private readonly byte[]? _llave;

    /// <summary>Modo receptor: solo verifica, no tiene palabra clave.</summary>
    public CifradoPropioAdapter() { }

    /// <summary>Modo emisor: la palabra clave es la llave privada.</summary>
    public CifradoPropioAdapter(string palabraClave) => _llave = CifradoPropio.DerivarLlavePublica(palabraClave);

    public string Nombre => CifradoPropio.NombreAlgoritmo;

    public string LlavePublica => CifradoPropio.ExportarLlave(LlaveOError());

    public byte[] CifrarConLlavePrivada(byte[] hash) => CifradoPropio.Cifrar(hash, LlaveOError());

    public byte[] DescifrarConLlavePublica(byte[] firma, string llavePublica) =>
        CifradoPropio.Descifrar(firma, CifradoPropio.ImportarLlave(llavePublica));

    /// <summary>La firma viaja escrita con las palabras del diccionario de login.js.</summary>
    public string FirmaATexto(byte[] firma) => Diccionario.BytesAPalabras(firma);

    public byte[] TextoAFirma(string texto) => Diccionario.PalabrasABytes(texto);

    private byte[] LlaveOError() =>
        _llave ?? throw new InvalidOperationException("Este adaptador se creó sin palabra clave (modo receptor).");
}
