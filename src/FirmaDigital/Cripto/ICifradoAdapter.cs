namespace FirmaDigital.Cripto;

/// <summary>
/// Interfaz objetivo (Target) del patrón adaptador para el algoritmo de llave privada / pública.
/// Firmar = cifrar el hash con la llave PRIVADA.
/// Verificar = descifrar la firma con la llave PÚBLICA y comparar con el hash recalculado.
/// </summary>
public interface ICifradoAdapter
{
    /// <summary>Nombre del algoritmo; viaja en el paquete para que el receptor sepa cuál usar.</summary>
    string Nombre { get; }

    /// <summary>Llave pública en texto, lista para enviarse junto al mensaje.</summary>
    string LlavePublica { get; }

    /// <summary>Cifra el hash con la llave privada. El resultado es la firma digital.</summary>
    byte[] CifrarConLlavePrivada(byte[] hash);

    /// <summary>Descifra la firma con la llave pública recibida y devuelve el hash que firmó el emisor.</summary>
    byte[] DescifrarConLlavePublica(byte[] firma, string llavePublica);

    /// <summary>Convierte la firma a texto para enviarla por la red (cada algoritmo define su formato).</summary>
    string FirmaATexto(byte[] firma);

    /// <summary>Operación inversa de FirmaATexto.</summary>
    byte[] TextoAFirma(string texto);
}
