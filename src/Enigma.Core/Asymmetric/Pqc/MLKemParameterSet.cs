namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// The ML-KEM parameter set (FIPS 203), selecting the security level of the module-lattice key
/// encapsulation mechanism. Higher values give a larger security margin at the cost of larger keys and
/// ciphertexts.
/// </summary>
public enum MLKemParameterSet
{
    /// <summary>ML-KEM-512 — NIST security category 1.</summary>
    MLKem512,

    /// <summary>ML-KEM-768 — NIST security category 3. The recommended default.</summary>
    MLKem768,

    /// <summary>ML-KEM-1024 — NIST security category 5.</summary>
    MLKem1024,
}
