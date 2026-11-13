using System.Security.Cryptography;
using System.Text;
using FirmaDigital.Red;

namespace FirmaDigital.Cripto;

/// <summary>Lo que produce el emisor: el paquete a enviar y los valores intermedios (para mostrarlos).</summary>
public sealed record ResultadoFirma(PaqueteFirmado Paquete, byte[] Hash, byte[] Firma, string HuellaLlavePublica);

/// <summary>Lo que concluye el receptor.</summary>
public sealed record ResultadoVerificacion(
    bool Valida, byte[] HashCalculado, byte[]? HashRecuperado, string Detalle, string HuellaLlavePublica);

/// <summary>
/// Cliente del patrón adaptador: implementa el proceso de firma digital usando solo las
/// interfaces IHashAdapter e ICifradoAdapter. Cambiar de librerías a algoritmos propios
/// no requiere tocar esta clase.
/// </summary>
public sealed class ServicioFirma(IHashAdapter hash, ICifradoAdapter cifrado)
{
    /// <summary>Emisor: 1) hashear el mensaje, 2) cifrar el hash con la llave privada, 3) empaquetar con la llave pública.</summary>
    public ResultadoFirma Firmar(string mensaje)
    {
        byte[] resumen = hash.CalcularHash(Encoding.UTF8.GetBytes(mensaje));
        byte[] firma = cifrado.CifrarConLlavePrivada(resumen);
        string llavePublica = cifrado.LlavePublica;

        var paquete = new PaqueteFirmado(mensaje, cifrado.FirmaATexto(firma), llavePublica, hash.Nombre, cifrado.Nombre);
        return new ResultadoFirma(paquete, resumen, firma, Huella(hash, llavePublica));
    }

    /// <summary>
    /// Receptor: 1) hashear el mensaje recibido, 2) descifrar la firma con la llave pública,
    /// 3) comparar ambos hashes. Si coinciden, el mensaje es auténtico e íntegro.
    /// </summary>
    public static ResultadoVerificacion Verificar(PaqueteFirmado paquete)
    {
        IHashAdapter hash = FabricaCripto.CrearHash(paquete.AlgoritmoHash);
        ICifradoAdapter cifrado = FabricaCripto.CrearCifradoVerificador(paquete.AlgoritmoCifrado);
        string huella = Huella(hash, paquete.LlavePublica);

        byte[] hashCalculado = hash.CalcularHash(Encoding.UTF8.GetBytes(paquete.Mensaje));

        byte[] hashRecuperado;
        try
        {
            byte[] firma = cifrado.TextoAFirma(paquete.Firma);
            hashRecuperado = cifrado.DescifrarConLlavePublica(firma, paquete.LlavePublica);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return new ResultadoVerificacion(false, hashCalculado, null,
                $"No se pudo descifrar la firma con la llave pública: {ex.Message}. La firma NO es auténtica.", huella);
        }

        bool coinciden = CryptographicOperations.FixedTimeEquals(hashCalculado, hashRecuperado);
        string detalle = coinciden
            ? "Los hashes coinciden: el mensaje es AUTÉNTICO (lo firmó el dueño de la llave privada) e ÍNTEGRO (no fue modificado)."
            : "Los hashes NO coinciden: el mensaje fue alterado en el camino o la firma no corresponde a esta llave pública.";
        return new ResultadoVerificacion(coinciden, hashCalculado, hashRecuperado, detalle, huella);
    }

    /// <summary>
    /// Huella corta de la llave pública. Emisor y receptor pueden compararla por otro medio
    /// (en persona, por chat) para confirmar que la llave pública no fue reemplazada.
    /// </summary>
    public static string Huella(IHashAdapter hash, string llavePublica)
    {
        byte[] h = hash.CalcularHash(Encoding.UTF8.GetBytes(llavePublica));
        return string.Join(":", h.Take(8).Select(b => b.ToString("x2")));
    }
}
