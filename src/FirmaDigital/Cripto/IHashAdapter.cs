namespace FirmaDigital.Cripto;

/// <summary>
/// Interfaz objetivo (Target) del patrón adaptador para funciones hash.
/// El resto del programa solo conoce esta interfaz; no sabe si detrás hay
/// una librería de C# (SHA-256) o el algoritmo propio (HashPropio-256).
/// </summary>
public interface IHashAdapter
{
    /// <summary>Nombre del algoritmo; viaja en el paquete para que el receptor sepa cuál usar.</summary>
    string Nombre { get; }

    /// <summary>Calcula el resumen (hash) de los datos. Debe ser determinista e irreversible.</summary>
    byte[] CalcularHash(byte[] datos);
}
