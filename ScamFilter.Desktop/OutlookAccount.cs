using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using ScamFilter;

namespace ScamFilter.Desktop
{
    /*
     * The app's registration with Microsoft (one for the whole app, not per person):
     *
     *   ClientId   the "Application (client) ID" Microsoft gives an app when it's registered.
     *              Microsoft only lets REGISTERED apps ask for permission to read mail. It isn't
     *              a secret (it's like the app's name tag), so it's normal to build it into the
     *              program: put yours in BuiltInClientId below and everyone using your build
     *              just clicks "Sign in with Microsoft". For testing, it can also be set without
     *              rebuilding: in the developer environment (Ctrl+Shift+D on the account window, or
     *              ScamFilter.exe --developer), use the Developer page's setup panel. That saves it
     *              in %LOCALAPPDATA%\ScamFilter\Developer\outlook.json, so it only applies there.
     *   Accounts   which kinds of Microsoft account can sign in. It has to match what was chosen
     *              when registering ("Supported account types"):
     *                common         personal (Outlook.com, Hotmail, Live) and work or school
     *                consumers      personal accounts only
     *                organizations  work or school accounts only
     */
    public class OutlookAppConfig
    {
        // Paste your app registration's Application (client) ID here, then rebuild.
        public const string BuiltInClientId = "";
        public const string BuiltInAccounts = "common";   // which kinds of Microsoft account can sign in (see above)

        public string ClientId = BuiltInClientId;   // the ID in use (built in, or from outlook.json)
        public string Accounts = BuiltInAccounts;   // the account types in use

        // Where a registration entered on the Developer page is saved.
        public static string FilePath
        {
            get { return Path.Combine(Paths.BaseDir, "outlook.json"); }
        }

        // Is there a usable registration? (Without one, the Outlook page says linking isn't set up.)
        public bool IsConfigured
        {
            get { return IsValidClientId(ClientId); }
        }

        // A client ID is a GUID: 8-4-4-4-12 hexadecimal digits, like 1a2b3c4d-1234-5678-9abc-def012345678.
        public static bool IsValidClientId(string id)
        {
            Guid parsed;
            return id != null && Guid.TryParseExact(id.Trim(), "D", out parsed);
        }

        // The registration: the built-in one, unless outlook.json has one.
        public static OutlookAppConfig Load()
        {
            OutlookAppConfig config = new OutlookAppConfig();
            if (!File.Exists(FilePath))
            {
                return config;
            }
            try
            {
                JsonDocument doc = JsonDocument.Parse(File.ReadAllText(FilePath));
                try
                {
                    string id = Json.Str(doc.RootElement, "clientId").Trim();
                    if (IsValidClientId(id))
                    {
                        config.ClientId = id;
                    }
                    string accounts = Json.Str(doc.RootElement, "accounts");
                    if (accounts == "common" || accounts == "consumers" || accounts == "organizations")
                    {
                        config.Accounts = accounts;
                    }
                }
                finally
                {
                    doc.Dispose();
                }
            }
            catch (Exception)
            {
                // A damaged file just means using the built-in registration.
            }
            return config;
        }

        // Saves the registration to outlook.json.
        public void Save()
        {
            Directory.CreateDirectory(Paths.BaseDir);
            MemoryStream buffer = new MemoryStream();
            Utf8JsonWriter writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true });
            writer.WriteStartObject();
            writer.WriteString("clientId", ClientId.Trim());
            writer.WriteString("accounts", Accounts);
            writer.WriteEndObject();
            writer.Flush();
            writer.Dispose();
            SharedFiles.WriteAtomically(FilePath, buffer.ToArray());
            buffer.Close();
        }

        // Version 1.2 kept "check every 5 minutes" in this same file; it's per account now.
        public static bool LegacyAutoCheck()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    JsonDocument doc = JsonDocument.Parse(File.ReadAllText(FilePath));
                    bool value = Json.Bool(doc.RootElement, "autoCheck", false);
                    doc.Dispose();
                    return value;
                }
            }
            catch (Exception)
            {
                // nothing to carry over
            }
            return false;
        }
    }

    // One account's Outlook setting (outlook.json in the account's folder).
    public class AccountOutlookSettings
    {
        public bool AutoCheck = false;   // check for new mail every few minutes while ScamFilter is open

        // Reads an account's Outlook settings (defaults if there's no file yet).
        public static AccountOutlookSettings Load(string accountFolder)
        {
            AccountOutlookSettings s = new AccountOutlookSettings();
            string path = Path.Combine(accountFolder, "outlook.json");
            if (File.Exists(path))
            {
                try
                {
                    JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
                    s.AutoCheck = Json.Bool(doc.RootElement, "autoCheck", false);
                    doc.Dispose();
                }
                catch (Exception)
                {
                    // a damaged file: automatic checks stay off
                }
            }
            return s;
        }

        // Saves them to the account's outlook.json.
        public void Save(string accountFolder)
        {
            Directory.CreateDirectory(accountFolder);
            SharedFiles.WriteAtomically(Path.Combine(accountFolder, "outlook.json"),
                "{\n  \"autoCheck\": " + (AutoCheck ? "true" : "false") + "\n}\n");
        }
    }

    // The saved sign-in has run out (or was never there): the user has to sign in again.
    public class SignInRequiredException : Exception
    {
        public SignInRequiredException() : base("Sign in to Outlook again.")
        {
        }
    }

    // Sending alerts needs a permission (Mail.Send) the user hasn't given yet.
    public class SendPermissionRequiredException : Exception
    {
        public SendPermissionRequiredException() : base("ScamFilter needs permission to send alert emails.")
        {
        }
    }

    /*
     * Signing in with a Microsoft account, using MSAL (Microsoft's sign-in library).
     *
     * How "Sign in with Microsoft" works (OAuth 2.0, the standard behind every "Sign in with..."):
     *   1. ScamFilter opens Microsoft's sign-in page in your web browser, saying which app is
     *      asking (the client ID) and for which permissions (the scopes below).
     *   2. You sign in on Microsoft's own page and agree. ScamFilter never sees your password.
     *   3. Microsoft sends the browser back to http://localhost (this PC), where MSAL is
     *      listening, with a one-time code. MSAL trades that code for:
     *        an ACCESS TOKEN   proof of permission, good for about an hour, sent with every
     *                          request to Graph (see GraphMailClient)
     *        a REFRESH TOKEN   used to get new access tokens without signing in again, for
     *                          up to about 90 days of not using the app
     *   4. The tokens are saved in outlook_signin.bin in the ScamFilter account's folder,
     *      encrypted by Windows (DPAPI) so only your Windows account on this PC can read them.
     *
     * Permissions ("scopes") asked for:
     *   User.Read    your name and email address
     *   Mail.Read    read your mail (can't change, delete, or move anything)
     *   Mail.Send    ONLY when alerts are turned on, and only used to email alerts to the
     *                contacts you picked. Asked for separately, so you see exactly when.
     * (MSAL adds offline_access, which is what allows the refresh token.)
     *
     * The same sign-in also proves who you are: a ScamFilter account linked to a Microsoft
     * account can be unlocked by signing in to Microsoft again (VerifyAsync).
     */
    public class OutlookAccount
    {
        // The permissions asked for at sign-in (see above), and the extra one for sending alerts.
        public static readonly string[] Scopes = { "User.Read", "Mail.Read" };
        public static readonly string[] SendScopes = { "Mail.Send" };

        // Where Microsoft's sign-in page sends the browser back to (a page on this PC), and the name
        // of the encrypted file the sign-in is saved in.
        private const string RedirectUri = "http://localhost";
        private const string CacheFileName = "outlook_signin.bin";

        private readonly IPublicClientApplication app;
        private MsalCacheHelper cacheHelper = null;
        private IAccount account = null;

        private OutlookAccount(IPublicClientApplication app)
        {
            this.app = app;
        }

        // The signed-in account's email address (or "" when nobody is signed in).
        public string UserName
        {
            get { return account == null || account.Username == null ? "" : account.Username; }
        }

        // MSAL's permanent ID for the signed-in Microsoft account (or "").
        public string HomeId
        {
            get { return account == null || account.HomeAccountId == null ? "" : account.HomeAccountId.Identifier; }
        }

        // Is someone signed in (now, or from a saved sign-in)?
        public bool IsSignedIn
        {
            get { return account != null; }
        }

        // cacheFolder: the ScamFilter account's folder, where its saved sign-in lives.
        public static async Task<OutlookAccount> CreateAsync(OutlookAppConfig config, string cacheFolder)
        {
            IPublicClientApplication app = PublicClientApplicationBuilder.Create(config.ClientId.Trim())
                .WithAuthority("https://login.microsoftonline.com/" + config.Accounts)
                .WithRedirectUri(RedirectUri)
                .WithClientName("ScamFilter")
                .Build();
            OutlookAccount outlook = new OutlookAccount(app);
            try
            {
                Directory.CreateDirectory(cacheFolder);
                StorageCreationProperties storage = new StorageCreationPropertiesBuilder(CacheFileName, cacheFolder).Build();
                outlook.cacheHelper = await MsalCacheHelper.CreateAsync(storage);
                outlook.cacheHelper.VerifyPersistence();
                outlook.cacheHelper.RegisterCache(app.UserTokenCache);
            }
            catch (Exception)
            {
                // Saving the sign-in isn't possible on this PC (rare). Signing in still works;
                // it just has to be done again each time the app starts.
                outlook.cacheHelper = null;
            }
            return outlook;
        }

        /*
         * Picks up a saved sign-in, without showing anything. True if there was one and it still
         * works (MSAL refreshes the access token quietly if it needs to). homeId: only accept that
         * Microsoft account (the one linked to this ScamFilter account).
         */
        public async Task<bool> ResumeAsync(string homeId, CancellationToken cancel)
        {
            account = null;
            foreach (IAccount a in await app.GetAccountsAsync())
            {
                if (homeId.Length == 0 || (a.HomeAccountId != null && a.HomeAccountId.Identifier == homeId))
                {
                    account = a;
                    break;
                }
            }
            if (account == null)
            {
                return false;
            }
            try
            {
                await app.AcquireTokenSilent(Scopes, account).ExecuteAsync(cancel);
                return true;
            }
            catch (MsalUiRequiredException)
            {
                account = null;   // saved, but it ran out or was taken back: sign in again
                return false;
            }
        }

        // The small pages the browser shows when signing in finishes (or fails).
        private static SystemWebViewOptions BrowserPages(string done)
        {
            SystemWebViewOptions page = new SystemWebViewOptions();
            page.HtmlMessageSuccess = "<html><body style=\"font-family:Segoe UI,sans-serif;margin:48px\">"
                + "<h2>" + done + "</h2><p>You can close this tab and go back to ScamFilter.</p></body></html>";
            page.HtmlMessageError = "<html><body style=\"font-family:Segoe UI,sans-serif;margin:48px\">"
                + "<h2>The sign-in didn't work.</h2><p>Go back to ScamFilter to see what happened.</p></body></html>";
            return page;
        }

        /*
         * Proves the person at the keyboard can sign in to the LINKED Microsoft account: Microsoft
         * asks for the password again (prompt=login, even if the browser remembers it), and the
         * account that signs in must be the linked one. Used to unlock ScamFilter's settings.
         */
        public async Task<bool> VerifyAsync(string homeId, string userName, CancellationToken cancel)
        {
            AuthenticationResult result = await app.AcquireTokenInteractive(Scopes)
                .WithUseEmbeddedWebView(false)
                .WithSystemWebViewOptions(BrowserPages("Confirmed. ScamFilter is unlocked."))
                .WithPrompt(Prompt.ForceLogin)
                .WithLoginHint(userName)
                .ExecuteAsync(cancel);
            bool same = result.Account != null && result.Account.HomeAccountId != null
                && result.Account.HomeAccountId.Identifier == homeId;
            if (same)
            {
                account = result.Account;
            }
            return same;
        }

        /*
         * A token for sending alerts. Throws SendPermissionRequiredException when the user hasn't
         * allowed sending yet (RequestSendPermissionAsync asks), never opening a window itself.
         */
        public async Task<string> GetSendTokenAsync(CancellationToken cancel)
        {
            if (account == null)
            {
                throw new SignInRequiredException();
            }
            try
            {
                AuthenticationResult result = await app.AcquireTokenSilent(SendScopes, account).ExecuteAsync(cancel);
                return result.AccessToken;
            }
            catch (MsalUiRequiredException)
            {
                throw new SendPermissionRequiredException();
            }
        }

        // Opens the browser so the user can allow sending alerts (the Mail.Send permission).
        public async Task RequestSendPermissionAsync(CancellationToken cancel)
        {
            AuthenticationResult result = await app.AcquireTokenInteractive(SendScopes)
                .WithAccount(account)
                .WithUseEmbeddedWebView(false)
                .WithSystemWebViewOptions(BrowserPages("ScamFilter can now send alerts."))
                .ExecuteAsync(cancel);
            account = result.Account;
        }

        // Opens the browser for the sign-in and waits until it's finished (or cancelled).
        public async Task SignInAsync(CancellationToken cancel)
        {
            AuthenticationResult result = await app.AcquireTokenInteractive(Scopes)
                .WithUseEmbeddedWebView(false)
                .WithSystemWebViewOptions(BrowserPages("ScamFilter is linked to your Microsoft account."))
                .WithPrompt(Prompt.SelectAccount)
                .ExecuteAsync(cancel);
            account = result.Account;
        }

        /*
         * An access token for the next Graph request. Uses the saved one while it's good and
         * refreshes it quietly when it isn't. Never opens the browser by itself (that would pop
         * up out of nowhere during an automatic check); throws SignInRequiredException instead.
         */
        public async Task<string> GetTokenAsync(CancellationToken cancel)
        {
            if (account == null)
            {
                throw new SignInRequiredException();
            }
            try
            {
                AuthenticationResult result = await app.AcquireTokenSilent(Scopes, account).ExecuteAsync(cancel);
                return result.AccessToken;
            }
            catch (MsalUiRequiredException)
            {
                account = null;   // the saved sign-in can't be used any more
                throw new SignInRequiredException();
            }
        }

        // Forgets the sign-in on this PC. (To take ScamFilter's access away completely, remove it
        // at account.microsoft.com > Privacy > Apps and services.)
        public async Task SignOutAsync()
        {
            foreach (IAccount a in await app.GetAccountsAsync())
            {
                await app.RemoveAsync(a);
            }
            account = null;
        }

        // Deletes a saved sign-in file (when the app registration changes, old sign-ins can't be reused).
        public static void ForgetSavedSignIn(string folder)
        {
            string path = Path.Combine(folder, CacheFileName);
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        // Version 1.2 kept the sign-in in the main folder; it's per account now.
        public static void MoveLegacySignIn(string toFolder)
        {
            string old = Path.Combine(Paths.BaseDir, CacheFileName);
            string target = Path.Combine(toFolder, CacheFileName);
            if (File.Exists(old) && !File.Exists(target))
            {
                Directory.CreateDirectory(toFolder);
                File.Move(old, target);
            }
        }

        /*
         * Sign-in errors in plain words. Microsoft's errors carry an "AADSTS" code; the common
         * ones all come from a detail of the app registration, so each says what to fix there.
         */
        public static string Explain(Exception ex)
        {
            string message = ex.Message ?? "";
            if (ex is OperationCanceledException)
            {
                return "Sign-in cancelled.";
            }
            MsalClientException client = ex as MsalClientException;
            if (client != null && client.ErrorCode == MsalError.AuthenticationCanceledError)
            {
                return "Sign-in cancelled.";
            }
            if (message.Contains("AADSTS700016"))
            {
                return "Microsoft doesn't know this app's registration for that kind of account. (Developer: check the "
                    + "Application (client) ID and that the supported account types include this kind of account.)";
            }
            if (message.Contains("AADSTS50011"))
            {
                return "The app registration is missing the redirect address. In the registration, open Authentication, "
                    + "add a platform \"Mobile and desktop applications\", and add the redirect URI http://localhost.";
            }
            if (message.Contains("AADSTS7000218") || message.Contains("AADSTS700025"))
            {
                return "The registration treats ScamFilter as a web app. In the registration, open Authentication and "
                    + "make sure http://localhost is under \"Mobile and desktop applications\", not under \"Web\". "
                    + "Then turn on \"Allow public client flows\" at the bottom of that page.";
            }
            if (message.Contains("AADSTS50020") || message.Contains("AADSTS50194") || message.Contains("AADSTS90072")
                || message.Contains("unauthorized_client"))
            {
                return "That kind of account can't sign in to this copy of ScamFilter. (Developer: set the app registration's "
                    + "supported account types to \"Any Entra ID tenant + Personal Microsoft accounts\".)";
            }
            if (message.Contains("AADSTS65001") || message.Contains("AADSTS90094") || message.Contains("AADSTS90008"))
            {
                return "Your organization has to approve ScamFilter before you can use it. Ask your IT admin, or sign in "
                    + "with a personal Microsoft account instead.";
            }
            if (message.Contains("AADSTS50076") || message.Contains("AADSTS50079"))
            {
                return "Your account needs a second sign-in step. Try signing in again and complete it in the browser.";
            }
            if (ex is System.Net.Http.HttpRequestException || message.Contains("No such host"))
            {
                return "Couldn't reach Microsoft. Check your internet connection and try again.";
            }
            return "The sign-in didn't work: " + FirstLine(message);
        }

        // The first line of a longer error message.
        private static string FirstLine(string s)
        {
            int newline = s.IndexOfAny(new char[] { '\r', '\n' });
            return newline >= 0 ? s.Substring(0, newline) : s;
        }
    }
}
