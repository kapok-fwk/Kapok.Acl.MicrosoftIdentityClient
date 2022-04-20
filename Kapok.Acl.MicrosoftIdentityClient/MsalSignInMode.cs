namespace Kapok.Acl.MicrosoftIdentityClient;

public enum MsalSignInMode
{
    /// <summary>
    /// Use account used to signed-in in Windows (WAM)
    /// </summary>
    UseSignedInWindowsAccount = 0,

    /// <summary>
    /// Use one of the Accounts known by Windows (WAM)
    /// </summary>
    UseKnownWindowsAccount,

    /// <summary>
    /// Use any account(Azure AD). It's not using WAM
    /// </summary>
    UseAnyAccount
}