using FirmaDigital.Cripto.Libreria;
using FirmaDigital.Cripto.Propio;

namespace FirmaDigital.Cripto;

/// <summary>
/// Crea el adaptador correcto a partir del nombre de algoritmo que viene en el paquete.
/// Así el receptor puede verificar mensajes firmados con cualquiera de los algoritmos.
/// </summary>
public static class FabricaCripto
{
    public static IHashAdapter CrearHash(string nombre) => nombre switch
    {
        Sha256Adapter.NombreAlgoritmo => new Sha256Adapter(),
        HashPropio.NombreAlgoritmo => new HashPropioAdapter(),
        _ => throw new NotSupportedException($"Algoritmo de hash desconocido: '{nombre}'."),
    };

    public static ICifradoAdapter CrearCifradoVerificador(string nombre) => nombre switch
    {
        RsaAdapter.NombreAlgoritmo => new RsaAdapter(),
        CifradoPropio.NombreAlgoritmo => new CifradoPropioAdapter(),
        _ => throw new NotSupportedException($"Algoritmo de cifrado desconocido: '{nombre}'."),
    };
}
