using System.Globalization;
using Microsoft.Identity.Client;

namespace Kapok.Acl.MicrosoftIdentityClient;

public class MsalAuthenticationService : ISilentAuthenticationService
{
    public string ProviderName => "MSAL";

    /// <summary>
    /// 
    /// </summary>
    /// <param name="clientId">
    /// ClientID (ApplicationID) of your application as registered in the App Registration (Preview) under Azure Active Directory in https://portal.azure.com
    /// </param>
    /// <param name="tenant">
    /// The content of Tenant by the information about the accounts allowed to sign-in in your application:
    ///   - For Work or School account in your org, use your tenant ID, or tenant domain (e.g. contoso.onmicrosoft.com)
    ///   - for any Work or School accounts, use organizations
    ///   - for any Work or School accounts, or Microsoft personal account, use common
    ///   - for Microsoft Personal account, use consumers
    ///
    /// This should be consistent with the audience of users who can sign-in, as specified during the application registration
    /// </param>
    /// <param name="aadInstance">
    /// Hostname for the Azure AD instance. {0} will be replaced by the value of <para>tenant</para>.
    /// 
    /// You can change this URL if you want your application to sign-in users from other clouds
    /// than the Azure Global Cloud (See national clouds / sovereign clouds at https://aka.ms/aadv2-national-clouds)
    /// 
    /// Default: https://login.microsoftonline.com/{0}/v2.0
    /// </param>
    /// <param name="scopes">
    /// Must include "user.read".
    /// </param>
    /// <param name="graphApiEndpoint">
    /// Set the API Endpoint to Graph 'me' endpoint. 
    /// To change from Microsoft public cloud to a national cloud, use another value of graphAPIEndpoint.
    /// Reference with Graph endpoints here: https://docs.microsoft.com/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
    /// </param>
    public MsalAuthenticationService(string clientId, string tenant, string? aadInstance = null, string[]? scopes = null)
    {
        _clientId = clientId ?? throw new ArgumentNullException(nameof(clientId));
        _tenant = tenant ?? throw new ArgumentNullException(nameof(tenant));
        _aadInstance = aadInstance ?? "https://login.microsoftonline.com/{0}/v2.0";

        Scopes = scopes;

        _clientApp = CreateApplication(false);
    }

    private readonly string _clientId;
    private readonly string _tenant;
    private readonly string _aadInstance;
    private readonly IPublicClientApplication _clientApp;
    private IAccount? _account;

    public string[]? Scopes { get; set; }

    /// <summary>
    /// Sets the sign in mode how to log in to your application.
    ///
    /// Default mode is <c>MsalSignInMode.UseSignedInWindowsAccount</c>.
    /// </summary>
    public MsalSignInMode SignInMode { get; set; } = MsalSignInMode.UseAnyAccount;

    private IPublicClientApplication CreateApplication(bool useWam)
    {
        var builder = PublicClientApplicationBuilder.Create(_clientId)
            .WithAuthority(string.Format(CultureInfo.InvariantCulture, _aadInstance, _tenant))
            .WithDefaultRedirectUri();

        if (useWam)
        {
            //builder.WithWindowsBroker(true);  // Requires redirect URI "ms-appx-web://microsoft.aad.brokerplugin/{client_id}" in app registration
            throw new NotSupportedException(
                $"Usage of WAM is not supported in the current version of {typeof(MsalAuthenticationService).FullName}");
        }
        var app = builder.Build();

        TokenCacheHelper.EnableSerialization(app.UserTokenCache);

        return app;
    }

    private async Task<IAccount?> GetFistAccount()
    {
        switch (SignInMode)
        {
            case MsalSignInMode.UseSignedInWindowsAccount:
                // WAM will always get an account in the cache. So if we want
                // to have a chance to select the accounts interactively, we need to
                // force the non-account
                return PublicClientApplication.OperatingSystemAccount;
            case MsalSignInMode.UseKnownWindowsAccount:
                // We force WAM to display the dialog with the accounts
                return null;
            case MsalSignInMode.UseAnyAccount:
                var accounts = await _clientApp.GetAccountsAsync();
                return accounts.FirstOrDefault();
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private async Task<bool> SilentLoginInternal(IAccount? account)
    {
        _account = null;
        AuthenticationResult? authResult;

        try
        {
            authResult = await _clientApp.AcquireTokenSilent(Scopes, account)
                .ExecuteAsync()
                .ConfigureAwait(false);
        }
        catch (MsalUiRequiredException ex)
        {
#if DEBUG
            // A MsalUiRequiredException happened on AcquireTokenSilent.
            // This indicates you need to call AcquireTokenInteractive to acquire a token
            System.Diagnostics.Debug.WriteLine($"MsalUiRequiredException: {ex.Message}");
#endif

            return false;
        }
        /*catch (Exception ex)
        {
            //ResultText.Text = $"Error Acquiring Token Silently:{System.Environment.NewLine}{ex}";
            return;
        }*/

        _account = authResult.Account;
        return true;
    }

    /// <summary>
    /// Tries to log in silently.
    /// </summary>
    /// <returns>
    /// True if silent login was successfully, otherwise false.
    /// </returns>
    public async Task<bool> SilentLogin()
    {
        IAccount? firstAccount = await GetFistAccount();

        return await SilentLoginInternal(firstAccount);
    }

    public async Task Login()
    {
        _account = null;
        IAccount? firstAccount = await GetFistAccount();

        AuthenticationResult? authResult;

        if (await SilentLoginInternal(firstAccount))
            return;

        try
        {
            authResult = await _clientApp.AcquireTokenInteractive(Scopes)
                .WithAccount(firstAccount)
                //.WithParentActivityOrWindow(new WindowInteropHelper(this).Handle) // optional, used to center the browser on the window
                .WithPrompt(Prompt.SelectAccount)
                .ExecuteAsync()
                .ConfigureAwait(false);
        }
        catch (MsalException msalex)
        {
            if (msalex.ErrorCode == "access_denied")
            {
                // The user canceled sign in, take no action.
                return;
            }

            // An unexpected error occurred.
            throw new NotSupportedException($"Unexpected error occurred during login: {msalex.ErrorCode}", msalex);
        }

        _account = authResult.Account;
    }

    public async Task Logout()
    {
        var accounts = (await _clientApp.GetAccountsAsync()).ToList();
        while (accounts.Any())
        {
            await _clientApp.RemoveAsync(accounts.First());
            accounts = (await _clientApp.GetAccountsAsync()).ToList();
        }
    }

    public string? UserName => _account?.Username;

    public string? UserEmail => _account?.Username;

    public string? UserAccountId => _account?.HomeAccountId?.Identifier;
}