using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;
using System.Windows.Threading;
using Microsoft.Identity.Client;

namespace ScamFilter.Desktop
{
    /*
     * The Outlook page: linking an Outlook account and checking its newest emails.
     * (A "partial class" is one class written in more than one file. This is the same
     * MainWindow as MainWindow.xaml.cs; the Outlook part just lives here to keep files readable.)
     *
     * Each ScamFilter account links its own Microsoft account (its sign-in lives in the account's
     * folder). Linking also lets that account be unlocked with Microsoft and send alerts.
     *
     * For now all of this is developer-only (App.ShowOutlook): the Outlook tab sits with the
     * developer tabs, and outside the developer environment ScamFilter never signs in to
     * Microsoft at all. ShowOrHideOutlookFeatures hides the Outlook parts of the other pages.
     *
     * The page has these states, and UpdateOutlookView shows the panel for the current one:
     *   no registration  this build has no Microsoft app registration (see OutlookAppConfig):
     *                    a short notice (in the developer environment, the registration can be
     *                    entered on the Developer page for testing)
     *   signed out       a "Sign in with Microsoft" button
     *   signed in        the folder list, with a verdict badge on every email
     *
     * Checking a folder:
     *   Graph: the newest emails, with their HTML and headers      (GraphMailClient.ListAsync)
     *   Graph: "have I ever emailed this sender?" for each sender  (GraphMailClient.HaveSentToAsync)
     *   ScamDetector.Check on every email, off the window's thread
     * Selecting an email downloads ALL of it (pictures too, for OCR), checks it again in full,
     * and shows the result on the Check page, where it can be marked, blocked, or trusted.
     */
    public partial class MainWindow
    {
        // How often the newest mail is checked when "Check for new mail" is on.
        private static readonly TimeSpan AutoCheckInterval = TimeSpan.FromMinutes(5);

        // The app's Microsoft registration (see OutlookAppConfig), and this account's Outlook
        // settings (automatic checks on or off).
        private OutlookAppConfig appConfig = new OutlookAppConfig();
        private AccountOutlookSettings outlookSettings = new AccountOutlookSettings();

        // The Microsoft sign-in (null until there's a registration) and the client that reads
        // mail through it.
        private OutlookAccount outlook = null;
        private GraphMailClient graph = null;

        // The rows of the Outlook page's list (the list on screen updates when this changes).
        private readonly ObservableCollection<OutlookItem> outlookItems = new ObservableCollection<OutlookItem>();

        // "Have I emailed this address?" answers, so each sender is only looked up once.
        private readonly Dictionary<string, bool?> sentToCache = new Dictionary<string, bool?>(StringComparer.OrdinalIgnoreCase);

        // Results of full checks (opened emails), so an automatic re-check doesn't replace them
        // with the quicker list check.
        private readonly Dictionary<string, Verdict> fullVerdicts = new Dictionary<string, Verdict>();

        private CancellationTokenSource signInCancel = null;   // set while waiting for the browser sign-in
        private DispatcherTimer outlookTimer = null;           // the 5-minute automatic check
        private bool outlookBusy = false;                      // a check is running right now
        private bool outlookCheckedOnce = false;               // the list has been filled at least once
        // The Outlook web link of the email shown on the Check page (for "Open in Outlook").
        private string checkPageOutlookLink = "";

        // This account's folder (its Outlook sign-in lives there).
        private string AccountFolder
        {
            get { return AccountStore.FolderOf(account); }
        }

        /*
         * Runs as soon as the window opens: sets up the page, and returns the task that picks up
         * a saved sign-in (that goes over the internet, so start-up carries on meanwhile).
         */
        private Task SetUpOutlookAsync()
        {
            OutlookList.ItemsSource = outlookItems;
            outlookTimer = new DispatcherTimer();
            outlookTimer.Interval = AutoCheckInterval;
            outlookTimer.Tick += OutlookTimer_Tick;
            appConfig = OutlookAppConfig.Load();
            outlookSettings = AccountOutlookSettings.Load(AccountFolder);
            AutoCheckBox.IsChecked = outlookSettings.AutoCheck;
            UpdateOutlookView();
            // With the Outlook features hidden, don't sign in to Microsoft at all.
            return appConfig.IsConfigured && App.ShowOutlook ? ResumeOutlookAsync() : Task.CompletedTask;
        }

        /*
         * Shows or hides the Outlook parts of the other pages (see App.ShowOutlook). The Outlook
         * tab itself is one of the developer tabs, so it shows and hides with them.
         */
        private void ShowOrHideOutlookFeatures()
        {
            Visibility outlookParts = App.ShowOutlook ? Visibility.Visible : Visibility.Collapsed;
            LinkOutlookTip.Visibility = outlookParts;      // Check page: "link your Outlook account"
            AlertsPanel.Visibility = outlookParts;         // Protections page: alerts go out through Outlook
            MicrosoftRowLabel.Visibility = outlookParts;   // Account page: the Microsoft account row
            AccountPageMicrosoft.Visibility = outlookParts;
            MicrosoftAccountButton.Visibility = outlookParts;
            if (App.ShowOutlook)
            {
                return;   // the pages' own wording already covers Outlook and alerts
            }
            ProtectionsSubtitle.Text = "Who to always warn you about, and who to trust. Anything that weakens your protection "
                + "(trusting someone, unblocking) asks for your password first.";
            AccountSubtitle.Text = "Each person on this PC has their own account, with their own blocked and trusted lists.";
        }

        // At start-up: picks up a saved sign-in (if any) without asking the person to sign in again.
        private async Task ResumeOutlookAsync()
        {
            SignInStatus.Text = "Looking for a saved sign-in...";
            try
            {
                await ConnectAsync();
                UpdateOutlookView();
                await outlook.ResumeAsync(account.MicrosoftHomeId, CancellationToken.None);
                SignInStatus.Text = "";
                if (outlook.IsSignedIn && !account.HasMicrosoft)
                {
                    // A sign-in carried over from version 1.2: it belongs to this account now.
                    LinkMicrosoft();
                }
            }
            catch (Exception)
            {
                // Offline, or the saved sign-in couldn't be read. Signing in again fixes either.
                SignInStatus.Text = "";
            }
            UpdateOutlookView();
            ShowAlertState();
        }

        // After start-up: the automatic check, if it's turned on.
        private async Task StartOutlookAutoCheckAsync()
        {
            if (OutlookSignedIn && outlookSettings.AutoCheck)
            {
                await RefreshOutlookAsync(true);
            }
        }

        // Creates the sign-in helper and the Graph client for this account's folder.
        private async Task ConnectAsync()
        {
            outlook = await OutlookAccount.CreateAsync(appConfig, AccountFolder);
            graph = new GraphMailClient(outlook.GetTokenAsync);
        }

        private bool OutlookSignedIn
        {
            get { return outlook != null && outlook.IsSignedIn; }
        }

        // Records that this ScamFilter account is linked to the signed-in Microsoft account.
        private void LinkMicrosoft()
        {
            account.MicrosoftHomeId = outlook.HomeId;
            account.MicrosoftUser = outlook.UserName;
            AccountStore.Save(store);
        }

        // Shows the panel for the current state (see the class comment).
        private void UpdateOutlookView()
        {
            bool configured = appConfig.IsConfigured;
            bool signedIn = configured && OutlookSignedIn;
            // Without an app registration there's nothing to sign in to. (In the developer
            // environment, the registration is entered on the Developer page.)
            OutlookUnavailablePanel.Visibility = !configured ? Visibility.Visible : Visibility.Collapsed;
            OutlookSignInPanel.Visibility = configured && !OutlookSignedIn ? Visibility.Visible : Visibility.Collapsed;
            OutlookToolbar.Visibility = signedIn ? Visibility.Visible : Visibility.Collapsed;
            OutlookListArea.Visibility = signedIn ? Visibility.Visible : Visibility.Collapsed;
            OutlookAccountBar.Visibility = signedIn ? Visibility.Visible : Visibility.Collapsed;
            OutlookUserText.Text = signedIn ? outlook.UserName : "";
            if (!signedIn)
            {
                OutlookStatus.Text = "";
            }

            if (outlookTimer != null && signedIn && outlookSettings.AutoCheck)
            {
                outlookTimer.Start();
            }
            else if (outlookTimer != null)
            {
                outlookTimer.Stop();
            }
            if (!OutlookSignedIn)
            {
                OutlookBadge.Visibility = Visibility.Collapsed;
            }
        }

        // The Outlook page was opened.
        private void OutlookPageShown()
        {
            if (OutlookSignedIn && !outlookCheckedOnce && !outlookBusy)
            {
                _ = RefreshOutlookAsync(false);
            }
        }

        // =====================================================================
        // Developer setup (the app registration's ID, on the Developer page), and signing in
        // =====================================================================

        // The Developer page was opened: show the registration that's saved now.
        private void DeveloperPageShown()
        {
            DevDataFolderText.Text = Paths.BaseDir;
            ClientIdBox.Text = appConfig.ClientId;
            foreach (object item in AccountsBox.Items)
            {
                ComboBoxItem option = item as ComboBoxItem;
                if (option != null && (option.Tag as string) == appConfig.Accounts)
                {
                    AccountsBox.SelectedItem = option;
                }
            }
        }

        // "Save and sign in" on the Developer page: saves the app registration's ID (a different
        // ID throws away the old sign-in), then signs in on the Outlook page.
        private async void OutlookSaveSetup_Click(object sender, RoutedEventArgs e)
        {
            string id = ClientIdBox.Text.Trim();
            if (!OutlookAppConfig.IsValidClientId(id))
            {
                SetupStatus.Text = "That doesn't look like an Application (client) ID. It's 32 letters and numbers in five "
                    + "groups, like 1a2b3c4d-1234-5678-9abc-def012345678. Copy it from the app's Overview page.";
                ClientIdBox.Focus();
                return;
            }
            ComboBoxItem choice = AccountsBox.SelectedItem as ComboBoxItem;
            string accounts = choice != null && choice.Tag is string ? (string) choice.Tag : "common";
            SetupStatus.Text = "";
            SaveSetupButton.IsEnabled = false;
            try
            {
                bool changed = outlook == null || id != appConfig.ClientId || accounts != appConfig.Accounts;
                if (changed)
                {
                    // A different registration can't reuse the old sign-in.
                    if (outlook != null)
                    {
                        try
                        {
                            await outlook.SignOutAsync();
                        }
                        catch (Exception)
                        {
                            // the old sign-in is being thrown away anyway
                        }
                    }
                    try
                    {
                        OutlookAccount.ForgetSavedSignIn(AccountFolder);
                    }
                    catch (IOException)
                    {
                        // still in use; signing out above already emptied it
                    }
                    ClearOutlookList();
                    appConfig.ClientId = id;
                    appConfig.Accounts = accounts;
                    appConfig.Save();
                    await ConnectAsync();
                }
                UpdateOutlookView();
                NavOutlook.IsChecked = true;   // signing in happens on the Outlook page
                if (!outlook.IsSignedIn)
                {
                    await SignInAsync();
                }
            }
            catch (Exception ex)
            {
                SetupStatus.Text = "Couldn't save the setup: " + ex.Message;
            }
            finally
            {
                SaveSetupButton.IsEnabled = true;
            }
        }

        // Enter in the app ID box does the same as the button.
        private void ClientIdBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Enter && SaveSetupButton.IsEnabled)
            {
                e.Handled = true;
                OutlookSaveSetup_Click(sender, null);
            }
        }

        // "Sign in with Microsoft".
        private async void OutlookSignIn_Click(object sender, RoutedEventArgs e)
        {
            await SignInAsync();
        }

        // "Cancel" while waiting for the browser sign-in.
        private void OutlookCancelSignIn_Click(object sender, RoutedEventArgs e)
        {
            if (signInCancel != null)
            {
                signInCancel.Cancel();
            }
        }

        // Signs in through the browser (Microsoft's own page), then links the Microsoft account to
        // this ScamFilter account and checks the inbox.
        private async Task SignInAsync()
        {
            if (signInCancel != null)
            {
                return;   // already waiting for one
            }
            if (outlook == null)
            {
                try
                {
                    await ConnectAsync();
                }
                catch (Exception ex)
                {
                    SignInStatus.Text = OutlookAccount.Explain(ex);
                    return;
                }
            }
            // Give up after 5 minutes, in case the browser tab was simply closed.
            signInCancel = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            SignInButton.IsEnabled = false;
            CancelSignInButton.Visibility = Visibility.Visible;
            SignInStatus.Text = "Finish signing in in your web browser. If no browser window opened, check the taskbar.";
            bool signedIn = false;
            try
            {
                await outlook.SignInAsync(signInCancel.Token);
                signedIn = true;
                SignInStatus.Text = "";
            }
            catch (Exception ex)
            {
                SignInStatus.Text = OutlookAccount.Explain(ex);
            }
            finally
            {
                signInCancel.Dispose();
                signInCancel = null;
                SignInButton.IsEnabled = true;
                CancelSignInButton.Visibility = Visibility.Collapsed;
            }
            if (!signedIn)
            {
                return;
            }
            Activate();   // the browser had the focus; bring ScamFilter back to the front

            // It has to be THIS account's Microsoft account, and no other ScamFilter account's.
            string problem = null;
            if (account.HasMicrosoft && account.MicrosoftHomeId != outlook.HomeId)
            {
                problem = "This ScamFilter account is linked to " + account.MicrosoftUser + ". Sign in with that one, or unlink it on the Account page first.";
            }
            foreach (Account other in store.Accounts)
            {
                if (other != account && other.MicrosoftHomeId == outlook.HomeId)
                {
                    problem = outlook.UserName + " is already linked to " + other.Name + "'s ScamFilter account.";
                }
            }
            if (problem != null)
            {
                try
                {
                    await outlook.SignOutAsync();
                }
                catch (Exception)
                {
                    // nothing was kept
                }
                await outlook.ResumeAsync(account.MicrosoftHomeId, CancellationToken.None);
                SignInStatus.Text = problem;
                UpdateOutlookView();
                return;
            }
            if (!account.HasMicrosoft)
            {
                LinkMicrosoft();
            }
            sentToCache.Clear();
            UpdateOutlookView();
            ShowAlertState();
            _ = alerts.FlushAsync();
            await RefreshOutlookAsync(false);
        }

        // "Unlink" at the top of the Outlook page.
        private async void OutlookSignOut_Click(object sender, RoutedEventArgs e)
        {
            await UnlinkMicrosoftAsync();
        }

        /*
         * Unlinks the Microsoft account: no more inbox checks, alerts, or unlocking with Microsoft.
         * That weakens protection, so it needs the password, and alert contacts hear about it
         * BEFORE the link is gone (alerts are sent through it). An account that opens ONLY with
         * Microsoft can't unlink until it has a password, or it couldn't be opened at all.
         */
        private async Task UnlinkMicrosoftAsync()
        {
            if (!account.HasPassword)
            {
                MessageBox.Show(this, "This account opens with your Microsoft account only, so unlinking it would lock you out.\n\n"
                    + "Set a password on the Account page first.", "Unlink Microsoft account", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (!await RequireUnlockAsync("Unlink " + (account.MicrosoftUser.Length > 0 ? account.MicrosoftUser : "Outlook") + "?",
                    "Unlinking stops ScamFilter from checking your inbox and from sending alerts, so it asks for your password first."))
            {
                return;
            }
            NoteChange("Outlook (" + account.MicrosoftUser + ") was unlinked: no more inbox checks or alerts");
            SendPendingChanges();
            await alerts.FlushAsync();
            if (outlook != null)
            {
                try
                {
                    await outlook.SignOutAsync();
                }
                catch (Exception ex)
                {
                    OutlookStatus.Text = "Couldn't sign out: " + ex.Message;
                    return;
                }
            }
            account.MicrosoftHomeId = "";
            account.MicrosoftUser = "";
            AccountStore.Save(store);
            ClearOutlookList();
            SignInStatus.Text = "Unlinked. ScamFilter no longer has a saved sign-in for this account.";
            UpdateOutlookView();
            ShowAlertState();
        }

        // Empties the list and everything remembered about it (used after unlinking or a new sign-in).
        private void ClearOutlookList()
        {
            outlookItems.Clear();
            fullVerdicts.Clear();
            sentToCache.Clear();
            outlookCheckedOnce = false;
            OutlookBadge.Visibility = Visibility.Collapsed;
        }

        // =====================================================================
        // Checking a folder
        // =====================================================================

        private async void OutlookRefresh_Click(object sender, RoutedEventArgs e)
        {
            await RefreshOutlookAsync(false);
        }

        // Inbox / Junk Email was switched: check that folder.
        private async void OutlookFolder_Checked(object sender, RoutedEventArgs e)
        {
            if (OutlookList == null || !OutlookSignedIn)
            {
                return;   // still being built, or nothing to show yet
            }
            outlookItems.Clear();
            await RefreshOutlookAsync(false);
        }

        // A different number of emails (25, 50, 100) was chosen: check again.
        private async void OutlookCount_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (OutlookList == null || !OutlookSignedIn || !outlookCheckedOnce)
            {
                return;
            }
            await RefreshOutlookAsync(false);
        }

        // "Check for new mail every 5 minutes". Turning it off weakens protection, so it needs the
        // password and is reported to alert contacts.
        private async void AutoCheck_Click(object sender, RoutedEventArgs e)
        {
            bool on = AutoCheckBox.IsChecked == true;
            if (!on)
            {
                // Turning automatic checks off weakens protection.
                if (!await RequireUnlockAsync("Stop checking for new mail?",
                        "Turning off automatic checks means new scam emails aren't caught on their own, so ScamFilter asks for your password first."))
                {
                    AutoCheckBox.IsChecked = true;
                    return;
                }
                NoteChange("Automatic checks for new Outlook mail were turned off");
            }
            outlookSettings.AutoCheck = on;
            try
            {
                outlookSettings.Save(AccountFolder);
                RememberFingerprint();
            }
            catch (Exception ex)
            {
                OutlookStatus.Text = "Couldn't save that setting: " + ex.Message;
            }
            UpdateOutlookView();
        }

        // Every 5 minutes, when automatic checks are on.
        private async void OutlookTimer_Tick(object sender, EventArgs e)
        {
            await RefreshOutlookAsync(true);
        }

        // The folder chosen at the top of the page, as Graph names it.
        private string SelectedFolder()
        {
            return FolderJunk.IsChecked == true ? GraphMailClient.Junk : GraphMailClient.Inbox;
        }

        // How many of the newest emails to check (25, 50, or 100).
        private int SelectedCount()
        {
            ComboBoxItem choice = OutlookCountBox.SelectedItem as ComboBoxItem;
            int count;
            if (choice != null && int.TryParse(choice.Tag as string, out count))
            {
                return count;
            }
            return 25;
        }

        /*
         * Gets the newest emails and checks them all. `automatic` means the 5-minute timer
         * started it: then nothing pops up, and problems only show in the status line.
         */
        private async Task RefreshOutlookAsync(bool automatic)
        {
            if (outlookBusy || !OutlookSignedIn)
            {
                return;
            }
            if (!ScamDetector.ModelExists())
            {
                if (!automatic)
                {
                    OutlookStatus.Text = "ScamFilter is still getting ready. Try again in a moment.";
                }
                return;
            }
            string folder = SelectedFolder();
            string folderName = folder == GraphMailClient.Junk ? "Junk Email" : "Inbox";
            int count = SelectedCount();

            outlookBusy = true;
            OutlookRefreshButton.IsEnabled = false;
            OutlookProgress.Visibility = Visibility.Visible;
            OutlookStatus.Text = "Getting your newest emails from " + folderName + "...";
            CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            try
            {
                List<GraphMailClient.MailItem> mail = await graph.ListAsync(folder, count, timeout.Token);
                OutlookStatus.Text = "Checking " + mail.Count + (mail.Count == 1 ? " email..." : " emails...");
                await FillRepliedAsync(mail, timeout.Token);

                // Checking runs off the window's thread, all emails in one go.
                List<Verdict> verdicts = await Task.Run(() =>
                {
                    List<Verdict> results = new List<Verdict>();
                    foreach (GraphMailClient.MailItem m in mail)
                    {
                        results.Add(ScamDetector.Check(m.Record));
                    }
                    return results;
                });

                // Only now, with everything ready, replace what's on screen (no half-filled list).
                outlookItems.Clear();
                int unsafeCount = 0;
                int cautionCount = 0;
                for (int i = 0; i < mail.Count; i++)
                {
                    Verdict full;
                    Verdict v = fullVerdicts.TryGetValue(mail[i].Id, out full) ? full : verdicts[i];
                    OutlookItem item = MakeOutlookItem(mail[i], v);
                    outlookItems.Add(item);
                    if (v.Band == ScamModel.Unsafe)
                    {
                        unsafeCount++;
                    }
                    else if (v.Band == ScamModel.Caution)
                    {
                        cautionCount++;
                    }
                }
                outlookCheckedOnce = true;

                // Alerts: one per unsafe email that arrived in the last day (older ones were
                // there before anyone could have been warned), never twice for the same email.
                for (int i = 0; i < mail.Count; i++)
                {
                    Verdict v = fullVerdicts.ContainsKey(mail[i].Id) ? fullVerdicts[mail[i].Id] : verdicts[i];
                    if (v.Band == ScamModel.Unsafe && DateTimeOffset.Now - mail[i].Received < TimeSpan.FromDays(1))
                    {
                        AlertAboutUnsafe(mail[i].Record, v, "outlook:" + mail[i].Id,
                            "in their Outlook " + (folder == GraphMailClient.Junk ? "junk folder" : "inbox"), mail[i].Received.LocalDateTime);
                    }
                }
                OutlookEmpty.Visibility = mail.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
                OutlookEmpty.Text = "No emails in " + folderName + ".";
                UpdateOutlookBadge();
                OutlookStatus.Text = "Checked " + mail.Count + (mail.Count == 1 ? " email" : " emails") + " in " + folderName
                    + " at " + DateTime.Now.ToString("h:mm tt") + ": " + unsafeCount + " unsafe, " + cautionCount + " caution."
                    + (mail.Count > 0 ? " Select an email for a full check and the reasons." : "");
            }
            catch (SignInRequiredException)
            {
                // The saved sign-in ran out (after about 90 days unused) or was taken back.
                ClearOutlookList();
                SignInStatus.Text = "Your Outlook sign-in has expired. Sign in again to keep checking your mail.";
                UpdateOutlookView();
            }
            catch (GraphException ex)
            {
                OutlookStatus.Text = ex.Status == 403
                    ? "Outlook didn't let ScamFilter read this folder. Sign out, sign in again, and agree to let ScamFilter read your mail."
                    : "Outlook couldn't do that: " + ex.Message;
            }
            catch (OperationCanceledException)
            {
                OutlookStatus.Text = "Outlook took too long to answer. Try again in a moment.";
            }
            catch (HttpRequestException)
            {
                OutlookStatus.Text = "Couldn't reach Outlook. Check your internet connection and try again.";
            }
            catch (MsalException ex)
            {
                OutlookStatus.Text = OutlookAccount.Explain(ex);
            }
            catch (Exception ex)
            {
                OutlookStatus.Text = "Couldn't check your Outlook mail: " + ex.Message;
            }
            finally
            {
                timeout.Dispose();
                outlookBusy = false;
                OutlookRefreshButton.IsEnabled = true;
                OutlookProgress.Visibility = Visibility.Hidden;
            }
        }

        /*
         * Fills in "have I emailed this sender?" (the user_has_replied flag) by searching Sent
         * Items, up to 4 searches at a time. A yes is evidence the sender is real; a no stays
         * "unknown", exactly like the unchecked box on the Check page.
         */
        private async Task FillRepliedAsync(List<GraphMailClient.MailItem> mail, CancellationToken cancel)
        {
            List<string> toLookUp = new List<string>();
            foreach (GraphMailClient.MailItem m in mail)
            {
                string address = m.FromAddress.Trim();
                bool isMe = address.Equals(outlook.UserName, StringComparison.OrdinalIgnoreCase);
                if (address.Length > 0 && !isMe && !sentToCache.ContainsKey(address) && !toLookUp.Contains(address, StringComparer.OrdinalIgnoreCase))
                {
                    toLookUp.Add(address);
                }
            }
            SemaphoreSlim gate = new SemaphoreSlim(4);
            Task<bool?>[] searches = new Task<bool?>[toLookUp.Count];
            for (int i = 0; i < toLookUp.Count; i++)
            {
                string address = toLookUp[i];
                searches[i] = Task.Run(async () =>
                {
                    await gate.WaitAsync(cancel);
                    try
                    {
                        return await graph.HaveSentToAsync(address, cancel);
                    }
                    finally
                    {
                        gate.Release();
                    }
                });
            }
            bool?[] answers = await Task.WhenAll(searches);
            gate.Dispose();
            for (int i = 0; i < toLookUp.Count; i++)
            {
                sentToCache[toLookUp[i]] = answers[i];
            }
            foreach (GraphMailClient.MailItem m in mail)
            {
                bool? sent;
                if (sentToCache.TryGetValue(m.FromAddress.Trim(), out sent) && sent == true)
                {
                    m.Record.UserHasReplied = true;
                }
            }
        }

        // One row of the list, from an email and its verdict.
        private OutlookItem MakeOutlookItem(GraphMailClient.MailItem m, Verdict v)
        {
            OutlookItem item = new OutlookItem();
            item.Mail = m;
            item.Verdict = v;
            item.BandText = BandName(v.Band);
            item.BandBrush = BandBrush(v.Band);
            item.From = m.FromName.Trim().Length > 0 ? m.FromName.Trim() : (m.FromAddress.Length > 0 ? m.FromAddress : "(no sender)");
            item.Subject = m.Subject.Trim().Length > 0 ? m.Subject.Trim() : "(no subject)";
            item.When = FriendlyTime(m.Received);
            item.Weight = m.IsRead ? FontWeights.Normal : FontWeights.SemiBold;
            item.Tip = (m.FromName.Length > 0 ? m.FromName + " <" + m.FromAddress + ">" : m.FromAddress)
                + "\n" + m.Record.Preview(220);
            return item;
        }

        // 3:04 PM today, Oct 20 this year, Oct 20, 2025 before that.
        private static string FriendlyTime(DateTimeOffset when)
        {
            if (when == default(DateTimeOffset))
            {
                return "";
            }
            DateTime local = when.ToLocalTime().DateTime;
            if (local.Date == DateTime.Today)
            {
                return local.ToString("h:mm tt");
            }
            if (local.Year == DateTime.Today.Year)
            {
                return local.ToString("MMM d");
            }
            return local.ToString("MMM d, yyyy");
        }

        // The red number next to "Outlook" in the navigation pane: unsafe emails in the last check.
        private void UpdateOutlookBadge()
        {
            int unsafeCount = 0;
            foreach (OutlookItem item in outlookItems)
            {
                if (item.Verdict != null && item.Verdict.Band == ScamModel.Unsafe)
                {
                    unsafeCount++;
                }
            }
            OutlookBadgeText.Text = unsafeCount > 99 ? "99+" : unsafeCount.ToString();
            OutlookBadge.Visibility = unsafeCount > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // =====================================================================
        // Opening one email for a full check
        // =====================================================================

        private async void OutlookList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            OutlookItem item = OutlookList.SelectedItem as OutlookItem;
            if (item == null)
            {
                return;
            }
            OutlookList.SelectedItem = null;   // so selecting the same row again works too
            await OpenOutlookItemAsync(item);
        }

        // Downloads the whole email (pictures too, for OCR), checks it again in full, and shows the
        // result on the Check page.
        private async Task OpenOutlookItemAsync(OutlookItem item)
        {
            NavCheck.IsChecked = true;
            CheckStatus.Text = "Getting the whole email from Outlook...";
            Verdict before = lastVerdict;
            CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            try
            {
                byte[] mime = await graph.DownloadMimeAsync(item.Mail.Id, timeout.Token);
                EmlImporter.Result result = await Task.Run(() =>
                {
                    MemoryStream stream = new MemoryStream(mime);
                    try
                    {
                        return EmlImporter.Load(stream);
                    }
                    finally
                    {
                        stream.Close();
                    }
                });
                result.Record.UserHasReplied = item.Mail.Record.UserHasReplied;
                result.Record.Source = "outlook";
                pendingOutlookKey = "outlook:" + item.Mail.Id;   // so an alert about it matches the list's
                await ImportEmailAsync(result, "Outlook");
                SetCheckPageOutlookLink(item.Mail.WebLink);

                // The full check (pictures read too) can differ from the list's quick one.
                if (lastVerdict != null && !ReferenceEquals(lastVerdict, before))
                {
                    item.Verdict = lastVerdict;
                    item.BandText = BandName(lastVerdict.Band);
                    item.BandBrush = BandBrush(lastVerdict.Band);
                    fullVerdicts[item.Mail.Id] = lastVerdict;
                    UpdateOutlookBadge();
                }
            }
            catch (Exception ex)
            {
                // Couldn't get the whole email: show the list's result, which is still a real check.
                ClearForm();
                FillForm(item.Mail.Record);
                ShowImportBar("From Outlook, checked without its pictures (" + DownloadProblem(ex) + ").");
                SetCheckPageOutlookLink(item.Mail.WebLink);
                ShowVerdict(item.Mail.Record, item.Verdict);
                CheckStatus.Text = "";
            }
            finally
            {
                timeout.Dispose();
            }
        }

        // Why downloading an email failed, in plain words.
        private static string DownloadProblem(Exception ex)
        {
            if (ex is SignInRequiredException)
            {
                return "the Outlook sign-in has expired";
            }
            if (ex is HttpRequestException)
            {
                return "couldn't reach Outlook";
            }
            if (ex is OperationCanceledException)
            {
                return "Outlook took too long";
            }
            return "the download didn't work";
        }

        // "Open in Outlook" under the message, only for emails that came from Outlook.
        private void SetCheckPageOutlookLink(string webLink)
        {
            checkPageOutlookLink = IsOutlookWebLink(webLink) ? webLink : "";
            OpenInOutlookText.Visibility = checkPageOutlookLink.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // Only ever open Microsoft's own Outlook addresses, never a link from inside an email.
        private static bool IsOutlookWebLink(string link)
        {
            Uri uri;
            if (string.IsNullOrEmpty(link) || !Uri.TryCreate(link, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                return false;
            }
            string host = uri.Host.ToLowerInvariant();
            return host == "outlook.live.com" || host == "outlook.office.com" || host == "outlook.office365.com"
                || host.EndsWith(".outlook.com", StringComparison.Ordinal);
        }

        // "Open in Outlook": opens the email in Outlook on the web (only an Outlook address is
        // ever opened; see IsOutlookWebLink).
        private void OpenInOutlook_Click(object sender, RoutedEventArgs e)
        {
            if (checkPageOutlookLink.Length == 0)
            {
                return;
            }
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = checkPageOutlookLink;
            info.UseShellExecute = true;   // opens the default web browser
            Process.Start(info);
        }

        // "Go to Outlook" on the Check page.
        private void GoToOutlook_Click(object sender, RoutedEventArgs e)
        {
            NavOutlook.IsChecked = true;
        }

        // Links in the app's own text (the setup steps). Never used for links inside messages.
        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = e.Uri.AbsoluteUri;
            info.UseShellExecute = true;
            Process.Start(info);
            e.Handled = true;
        }
    }
}
