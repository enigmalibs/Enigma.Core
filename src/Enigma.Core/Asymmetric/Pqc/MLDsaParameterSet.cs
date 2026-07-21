namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// The ML-DSA parameter set (FIPS 204), selecting the security level of the module-lattice digital
/// signature algorithm. Higher values give a larger security margin at the cost of larger keys and
/// signatures.
/// </summary>
public enum MLDsaParameterSet
{
    /// <summary>ML-DSA-44 — NIST security category 2.</summary>
    MLDsa44,

    /// <summary>ML-DSA-65 — NIST security category 3. The recommended default.</summary>
    MLDsa65,

    /// <summary>ML-DSA-87 — NIST security category 5.</summary>
    MLDsa87,
}
