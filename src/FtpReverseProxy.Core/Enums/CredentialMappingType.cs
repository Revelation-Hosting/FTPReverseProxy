namespace FtpReverseProxy.Core.Enums;

/// <summary>
/// Types of credential mapping between client and backend
/// </summary>
public enum CredentialMappingType
{
    /// <summary>
    /// Pass through client credentials to backend unchanged
    /// </summary>
    Passthrough,

    /// <summary>
    /// Use a fixed service account for all connections to this backend
    /// </summary>
    ServiceAccount,

    /// <summary>
    /// Map specific client users to specific backend credentials
    /// </summary>
    Mapped,

    /// <summary>
    /// Same username, but use an internally known password
    /// </summary>
    SameUserInternalPassword
}
