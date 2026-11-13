namespace FirmaDigital.Cripto.Propio;

/// <summary>Adaptador del algoritmo propio HashPropio (Adaptee) a IHashAdapter (Target).</summary>
public sealed class HashPropioAdapter : IHashAdapter
{
    public string Nombre => HashPropio.NombreAlgoritmo;

    public byte[] CalcularHash(byte[] datos) => HashPropio.Calcular(datos);
}
