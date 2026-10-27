using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace ScamFilter.Desktop
{
    // One row of the Blocked or Trusted list, as the page shows it.
    public class EntryRowItem
    {
        public string Icon { get; set; }       // the icon (phone, envelope, or globe)
        public string Title { get; set; }      // the entry, as it's shown
        public string Subtitle { get; set; }   // its label, or what kind of entry it is
        public ListEntry Entry { get; set; }   // the entry itself (for "Remove")
        public bool Blocked { get; set; }      // on the Blocked list (true) or the Trusted list
    }

    /*
     * The Protections page: the Blocked and Trusted lists, and alerts.
     *
     * ============================================================================
     *  WHAT NEEDS THE PASSWORD
     * ============================================================================
     * Anything that WEAKENS protection, because that's what a scammer on the phone would ask
     * someone to do ("just add my number to your trusted list"):
     *     trusting a sender, unblocking one, removing an alert contact, adding one,
     *     turning an alert off, turning automatic Outlook checks off, unlinking Outlook
     * Anything that STRENGTHENS it is free: blocking, removing a trusted entry, turning alerts on.
     *
     * After the password, protections stay unlocked for UnlockMinutes (so a few changes in a
     * row don't ask every time), then lock again by themselves. "Lock now" locks right away.
     *
     * ============================================================================
     *  ALERTS ABOUT CHANGES
     * ============================================================================
     * Changes made while unlocked are collected in pendingChanges and sent as ONE alert when
     * protections lock again (one email instead of five). Two kinds go out right away instead,
     * BEFORE they take effect: removing an alert contact (so that person hears about it) and
     * turning an alert off (so the alert isn't switched off before it can say so).
     */
    public partial class MainWindow
    {
        private const int UnlockMinutes = 5;   // how long protections stay unlocked after the password

        private List<ListEntry> blockedEntries = new List<ListEntry>();   // the Blocked list, as last read
        private List<ListEntry> trustedEntries = new List<ListEntry>();   // the Trusted list, as last read
        private AlertService alerts = null;                               // this account's alerts
        private DateTime unlockedUntilUtc = DateTime.MinValue;            // unlocked until this time
        private DispatcherTimer lockTimer = null;                         // updates the lock pill every 15 seconds
        private DispatcherTimer alertRetryTimer = null;                   // retries waiting alerts every 3 minutes
        private readonly List<string> pendingChanges = new List<string>();   // changes to report when it locks

        // Set just before an email from Outlook is checked on the Check page, so an alert about
        // it uses the same key as the Outlook page's alert (and it's never sent twice).
        private string pendingOutlookKey = "";

        // Runs once when the window opens.
        private void SetUpProtections()
        {
            alerts = new AlertService(account, GetOutlookForAlertsAsync);
            alerts.Changed += () => Dispatcher.BeginInvoke(new Action(ShowAlertState));
            LoadLists();
            lockTimer = new DispatcherTimer();
            lockTimer.Interval = TimeSpan.FromSeconds(15);
            lockTimer.Tick += (s, e) => UpdateLockState();
            lockTimer.Start();
            alertRetryTimer = new DispatcherTimer();
            alertRetryTimer.Interval = TimeSpan.FromMinutes(3);
            alertRetryTimer.Tick += (s, e) =>
            {
                if (alerts.Log.Waiting.Count > 0)
                {
                    _ = alerts.FlushAsync();
                }
            };
            alertRetryTimer.Start();
            UpdateLockState();
        }

        // The Outlook sign-in the alerts are sent through (null when Outlook isn't linked).
        private Task<OutlookAccount> GetOutlookForAlertsAsync()
        {
            return Task.FromResult(outlook);
        }

        // The page was opened.
        private void ShowProtections()
        {
            LoadLists();
            ShowLists();
            alerts.ReloadSettings();   // up to date, even if another window changed them
            ShowAlertSettings();
            ShowAlertState();
            UpdateLockState();
        }

        // ------------------------------------------------------------------
        // The lists
        // ------------------------------------------------------------------

        private string ListPath(bool blocked)
        {
            return Paths.ListFile(blocked ? "blocklist.txt" : "whitelist.txt");
        }

        // Reads both lists from the account's folder (another window may have changed them).
        private void LoadLists()
        {
            blockedEntries = ProtectionLists.Load(ListPath(true));
            trustedEntries = ProtectionLists.Load(ListPath(false));
        }

        // Writes both lists, tells the detector to reread them, and updates the tripwire.
        private void SaveLists()
        {
            ProtectionLists.Save(ListPath(true), blockedEntries, true);
            ProtectionLists.Save(ListPath(false), trustedEntries, false);
            ScamDetector.ReloadLists();
            RememberFingerprint();
        }

        // The user's own addresses, which can't be blocked or be alert contacts.
        private List<string> OwnAddresses()
        {
            List<string> own = new List<string>();
            if (account.MicrosoftUser.Length > 0)
            {
                own.Add(account.MicrosoftUser);
            }
            if (outlook != null && outlook.UserName.Length > 0)
            {
                own.Add(outlook.UserName);
            }
            return own;
        }

        // Puts both lists on the page.
        private void ShowLists()
        {
            BlockList.ItemsSource = Rows(blockedEntries, true);
            TrustList.ItemsSource = Rows(trustedEntries, false);
            BlockEmpty.Visibility = blockedEntries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            TrustEmpty.Visibility = trustedEntries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // The page's rows for a list, newest first.
        private static List<EntryRowItem> Rows(List<ListEntry> entries, bool blocked)
        {
            List<EntryRowItem> rows = new List<EntryRowItem>();
            for (int i = entries.Count - 1; i >= 0; i--)   // newest first
            {
                ListEntry e = entries[i];
                EntryRowItem row = new EntryRowItem();
                row.Entry = e;
                row.Blocked = blocked;
                bool unreadable = e.Label == ProtectionLists.UnreadableMark;
                row.Icon = e.Kind == EntryKind.Phone ? char.ConvertFromUtf32(0xE717)
                    : (e.Kind == EntryKind.Email ? char.ConvertFromUtf32(0xE715) : char.ConvertFromUtf32(0xE774));
                row.Title = e.Label.Length > 0 && !unreadable ? e.Label : e.Display;
                row.Subtitle = unreadable ? "Not understood (typed into the file by hand). Remove it and add it again."
                    : (e.Label.Length > 0 ? e.Display + "  -  " + e.KindName : e.KindName);
                rows.Add(row);
            }
            return rows;
        }

        // Enter in the "block" box does the same as the Block button.
        private void BlockInput_KeyDown(object sender, KeyEventArgs e)
        {
            BlockStatus.Text = "";
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                AddBlocked_Click(sender, null);
            }
        }

        // Enter in the "trust" box does the same as the Trust button.
        private void TrustInput_KeyDown(object sender, KeyEventArgs e)
        {
            TrustStatus.Text = "";
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                AddTrusted_Click(sender, null);
            }
        }

        // "Block": free, since blocking only adds protection.
        private void AddBlocked_Click(object sender, RoutedEventArgs e)
        {
            string result = AddToBlocked(BlockInput.Text, BlockLabel.Text);
            bool ok = result.StartsWith("Blocked", StringComparison.Ordinal);
            SetStatus(BlockStatus, result, ok);
            if (ok)
            {
                BlockInput.Clear();
                BlockLabel.Clear();
            }
            BlockInput.Focus();
        }

        // "Trust": checked against the rules first, then needs the password.
        private async void AddTrusted_Click(object sender, RoutedEventArgs e)
        {
            string result = await AddToTrustedAsync(TrustInput.Text, TrustLabel.Text);
            bool ok = result.StartsWith("Trusted", StringComparison.Ordinal);
            SetStatus(TrustStatus, result, ok);
            if (ok)
            {
                TrustInput.Clear();
                TrustLabel.Clear();
            }
            TrustInput.Focus();
        }

        // Shows a short result under a box, green for done, red for refused.
        private void SetStatus(TextBlock status, string text, bool ok)
        {
            status.Text = text;
            status.Foreground = (Brush) FindResource(ok ? "SafeBrush" : "UnsafeBrush");
        }

        /*
         * Blocks something. Free (blocking only strengthens protection). Returns what happened,
         * in words: "Blocked ..." on success, otherwise the rule that refused it.
         */
        private string AddToBlocked(string input, string label)
        {
            LoadLists();
            ListRules.Result r = ListRules.Check(input, label, true, blockedEntries, trustedEntries, OwnAddresses());
            if (!r.Ok)
            {
                return r.Message;
            }
            blockedEntries.Add(r.Entry);
            SaveLists();
            ShowLists();
            return "Blocked " + r.Entry.Display + "." + (r.Message.Length > 0 ? " " + r.Message : "");
        }

        /*
         * Trusts something. The rules are checked FIRST, so a refused entry never asks for the
         * password; then the password, then it's saved and noted for the change alert.
         */
        private async Task<string> AddToTrustedAsync(string input, string label)
        {
            LoadLists();
            ListRules.Result r = ListRules.Check(input, label, false, trustedEntries, blockedEntries, OwnAddresses());
            if (!r.Ok)
            {
                return r.Message;
            }
            bool unlocked = await RequireUnlockAsync("Trust " + r.Entry.Display + "?",
                "Messages from trusted senders are marked Safe. Scammers often ask people to trust their number, "
                + "so ScamFilter asks for your password first.");
            if (!unlocked)
            {
                return "Not trusted: that needs your password.";
            }
            LoadLists();   // (re-read, in case it changed while the password dialog was open)
            r = ListRules.Check(input, label, false, trustedEntries, blockedEntries, OwnAddresses());
            if (!r.Ok)
            {
                return r.Message;
            }
            trustedEntries.Add(r.Entry);
            SaveLists();
            ShowLists();
            NoteChange("Trusted " + r.Entry.Display + (r.Entry.Label.Length > 0 ? " (" + r.Entry.Label + ")" : ""));
            return "Trusted " + r.Entry.Display + "." + (r.Message.Length > 0 ? " " + r.Message : "");
        }

        // "Remove" on a row. Unblocking needs the password; removing a trusted entry doesn't.
        private async void RemoveEntry_Click(object sender, RoutedEventArgs e)
        {
            EntryRowItem row = ((FrameworkElement) sender).DataContext as EntryRowItem;
            if (row == null)
            {
                return;
            }
            if (row.Blocked)
            {
                bool unlocked = await RequireUnlockAsync("Unblock " + row.Entry.Display + "?",
                    "Unblocking lets its messages through without an automatic warning, so ScamFilter asks for your password first.");
                if (!unlocked)
                {
                    SetStatus(BlockStatus, "Still blocked: unblocking needs your password.", false);
                    return;
                }
            }
            LoadLists();
            List<ListEntry> list = row.Blocked ? blockedEntries : trustedEntries;
            list.RemoveAll(x => x.Key == row.Entry.Key && x.Value == row.Entry.Value);
            SaveLists();
            ShowLists();
            if (row.Blocked)
            {
                NoteChange("Unblocked " + row.Entry.Display);
                SetStatus(BlockStatus, "Unblocked " + row.Entry.Display + ".", true);
            }
            else
            {
                SetStatus(TrustStatus, "Removed " + row.Entry.Display + " from your trusted list.", true);
            }
        }

        // ------------------------------------------------------------------
        // Locking and unlocking
        // ------------------------------------------------------------------

        private bool IsUnlocked
        {
            get { return DateTime.UtcNow < unlockedUntilUtc; }
        }

        /*
         * True if protections are unlocked, asking for the password (or Microsoft) if they aren't.
         * heading and purpose are what the dialog says: what's about to happen, and why it asks.
         */
        private async Task<bool> RequireUnlockAsync(string heading, string purpose)
        {
            if (IsUnlocked || App.DeveloperMode)
            {
                return true;   // (the developer environment has no password: see App.xaml.cs)
            }
            UnlockDialog dialog = new UnlockDialog(this, store, account, heading, purpose,
                account.HasMicrosoft && appConfig.IsConfigured ? (Func<Task<OutlookAccount>>) GetOutlookForUnlockAsync : null, OnLockedOut);
            bool ok = dialog.ShowDialog() == true;
            if (dialog.NewRecoveryCode.Length > 0)
            {
                new CodeDialog(this, dialog.NewRecoveryCode).ShowDialog();
                NoteChange("The password was reset with the recovery code");
            }
            if (ok)
            {
                unlockedUntilUtc = DateTime.UtcNow.AddMinutes(UnlockMinutes);
                UpdateLockState();
            }
            await Task.CompletedTask;
            return ok;
        }

        // The Outlook sign-in, for unlocking with Microsoft instead of the password.
        private async Task<OutlookAccount> GetOutlookForUnlockAsync()
        {
            if (outlook == null)
            {
                await ConnectAsync();
            }
            return outlook;
        }

        // 5 wrong passwords in a row (see UnlockDialog): alert, if that's turned on.
        private void OnLockedOut(Account a, int attempts, int minutes)
        {
            alerts.Raise(AlertComposer.WrongPassword(a.Name, attempts, Math.Max(1, minutes), DateTime.Now));
        }

        // "Unlock" / "Lock now".
        private void LockButton_Click(object sender, RoutedEventArgs e)
        {
            if (IsUnlocked)
            {
                LockProtections();
            }
            else
            {
                _ = RequireUnlockAsync("Unlock protections", "Unlock to change your lists and alerts without being asked each time.");
            }
        }

        // Locks now, and sends the alert about whatever changed while unlocked.
        private void LockProtections()
        {
            unlockedUntilUtc = DateTime.MinValue;
            SendPendingChanges();
            UpdateLockState();
        }

        // Updates the lock pill ("Locked" / "Unlocked for 4 more minutes"), and locks again once
        // the time is up.
        private void UpdateLockState()
        {
            if (LockText == null)
            {
                return;
            }
            if (!IsUnlocked && unlockedUntilUtc != DateTime.MinValue)
            {
                unlockedUntilUtc = DateTime.MinValue;   // just ran out
                SendPendingChanges();
            }
            if (App.DeveloperMode)
            {
                LockIcon.Text = char.ConvertFromUtf32(0xE785);   // open padlock
                LockText.Text = "No password in the developer environment";
                LockButton.Visibility = Visibility.Collapsed;
                LockPill.Background = new SolidColorBrush(Color.FromRgb(0xFF, 0xF4, 0xCE));
            }
            else if (IsUnlocked)
            {
                int minutes = (int) Math.Ceiling((unlockedUntilUtc - DateTime.UtcNow).TotalMinutes);
                LockIcon.Text = char.ConvertFromUtf32(0xE785);   // open padlock
                LockText.Text = "Unlocked for " + minutes + (minutes == 1 ? " more minute" : " more minutes");
                LockButton.Content = "Lock now";
                LockPill.Background = new SolidColorBrush(Color.FromRgb(0xFF, 0xF4, 0xCE));
            }
            else
            {
                LockIcon.Text = char.ConvertFromUtf32(0xE72E);   // padlock
                LockText.Text = "Locked";
                LockButton.Content = "Unlock";
                LockPill.Background = (Brush) FindResource("NavSelectedBrush");
            }
        }

        // ------------------------------------------------------------------
        // Alerts: settings
        // ------------------------------------------------------------------

        private bool showingAlertSettings = false;   // true while the boxes are being filled in by code

        // Puts the alert settings on the page (contacts and the three switches).
        private void ShowAlertSettings()
        {
            showingAlertSettings = true;
            ContactList.ItemsSource = null;
            ContactList.ItemsSource = new List<AlertContact>(alerts.Settings.Contacts);
            ContactsEmpty.Visibility = alerts.Settings.Contacts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            AddContactRow.Visibility = alerts.Settings.Contacts.Count < AlertSettings.MaxContacts ? Visibility.Visible : Visibility.Collapsed;
            AlertUnsafeBox.IsChecked = alerts.Settings.OnUnsafe;
            AlertPasswordBox.IsChecked = alerts.Settings.OnWrongPassword;
            AlertChangeBox.IsChecked = alerts.Settings.OnProtectionChange;
            TestAlertButton.IsEnabled = alerts.Settings.Contacts.Count > 0;
            showingAlertSettings = false;
        }

        // Saves the alert settings, updates the tripwire, and redraws them.
        private void SaveAlertSettings()
        {
            alerts.Settings.Save(AccountStore.FolderOf(account));
            RememberFingerprint();
            ShowAlertSettings();
        }

        // Enter in the contact's email box does the same as "Add".
        private void ContactEmail_KeyDown(object sender, KeyEventArgs e)
        {
            ContactStatus.Text = "";
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                AddContact_Click(sender, null);
            }
        }

        // "Add" an alert contact: checked, then needs the password (nobody may quietly add themselves).
        private async void AddContact_Click(object sender, RoutedEventArgs e)
        {
            string clean;
            string problem = alerts.Settings.WhyContactNotAllowed(ContactNameInput.Text, ContactEmailInput.Text, OwnAddresses(), out clean);
            if (problem != null)
            {
                SetStatus(ContactStatus, problem, false);
                return;
            }
            bool unlocked = await RequireUnlockAsync("Add an alert contact?",
                "Changing who gets alerts asks for your password, so nobody can quietly add themselves.");
            if (!unlocked)
            {
                SetStatus(ContactStatus, "Not added: that needs your password.", false);
                return;
            }
            alerts.ReloadSettings();   // (another window may have changed them)
            AlertContact contact = new AlertContact();
            contact.Name = ContactNameInput.Text.Trim();
            contact.Email = clean;
            alerts.Settings.Contacts.Add(contact);
            SaveAlertSettings();
            NoteChange("Added " + contact.Name + " (" + contact.Email + ") as an alert contact");
            ContactNameInput.Clear();
            ContactEmailInput.Clear();
            SetStatus(ContactStatus, "Added " + contact.Name + ". Send a test alert to make sure it arrives.", true);
            ShowAlertState();
        }

        // "Remove" an alert contact: needs the password, and that person gets one last alert first.
        private async void RemoveContact_Click(object sender, RoutedEventArgs e)
        {
            AlertContact contact = ((FrameworkElement) sender).DataContext as AlertContact;
            if (contact == null)
            {
                return;
            }
            bool unlocked = await RequireUnlockAsync("Remove " + contact.Name + " from alerts?",
                "Changing who gets alerts asks for your password. " + contact.Name + " gets one last email saying they were removed.");
            if (!unlocked)
            {
                return;
            }
            // Tell everyone, the removed person included, BEFORE they're removed.
            NoteChange("Removed " + contact.Name + " (" + contact.Email + ") from alert contacts");
            SendPendingChanges();
            alerts.ReloadSettings();
            alerts.Settings.Contacts.RemoveAll(c => c.Email == contact.Email);
            SaveAlertSettings();
            SetStatus(ContactStatus, "Removed " + contact.Name + ".", true);
        }

        // One of the three alert switches. Turning one off needs the password and is reported first.
        private async void AlertToggle_Click(object sender, RoutedEventArgs e)
        {
            if (showingAlertSettings)
            {
                return;
            }
            CheckBox box = (CheckBox) sender;
            bool turningOn = box.IsChecked == true;
            string what = box == AlertUnsafeBox ? "unsafe messages" : (box == AlertPasswordBox ? "wrong passwords" : "protection changes");
            if (!turningOn)
            {
                bool unlocked = await RequireUnlockAsync("Turn off alerts about " + what + "?",
                    "Turning an alert off weakens your protection, so ScamFilter asks for your password first.");
                if (!unlocked)
                {
                    box.IsChecked = true;
                    return;
                }
                NoteChange("Turned off alerts about " + what);
                SendPendingChanges();   // before it's off, so this alert still goes out
            }
            alerts.ReloadSettings();
            if (box == AlertUnsafeBox)
            {
                alerts.Settings.OnUnsafe = turningOn;
            }
            else if (box == AlertPasswordBox)
            {
                alerts.Settings.OnWrongPassword = turningOn;
            }
            else
            {
                alerts.Settings.OnProtectionChange = turningOn;
            }
            SaveAlertSettings();
        }

        // "Send a test alert" to every contact.
        private async void TestAlert_Click(object sender, RoutedEventArgs e)
        {
            TestAlertButton.IsEnabled = false;
            ContactStatus.Foreground = (Brush) FindResource("TextSecondaryBrush");
            ContactStatus.Text = "Sending...";
            alerts.Raise(AlertComposer.Test(account.Name));
            await alerts.FlushAsync();
            TestAlertButton.IsEnabled = alerts.Settings.Contacts.Count > 0;
            if (alerts.Problem.Length == 0)
            {
                SetStatus(ContactStatus, "Test alert sent. Ask them to check their inbox (and junk folder).", true);
            }
            else
            {
                SetStatus(ContactStatus, "Not sent yet: see the note above.", false);
            }
        }

        // ------------------------------------------------------------------
        // Alerts: what's in the way, and fixing it
        // ------------------------------------------------------------------

        private void ShowAlertState()
        {
            if (AlertProblemBar == null || alerts == null)
            {
                return;
            }
            bool linked = outlook != null && outlook.IsSignedIn;
            AlertSendingFrom.Text = linked ? "Sent from " + outlook.UserName + "." : "";
            string problem = alerts.Problem;
            if (problem.Length == 0 && !linked && alerts.Settings.Contacts.Count > 0)
            {
                problem = "Alerts are sent from your Outlook account, and it isn't linked yet. Link it on the Outlook page.";
            }
            int waiting = alerts.Log.Waiting.Count;
            if (problem.Length > 0 && waiting > 0)
            {
                problem += " (" + waiting + (waiting == 1 ? " alert is" : " alerts are") + " waiting to go out.)";
            }
            AlertProblemBar.Visibility = problem.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
            AlertProblemText.Text = problem;
            if (problem.Contains("needs your OK"))
            {
                AlertFixButton.Content = "Allow sending";
                AlertFixButton.Visibility = Visibility.Visible;
            }
            else if (problem.Contains("Outlook page"))
            {
                AlertFixButton.Content = "Go to Outlook";
                AlertFixButton.Visibility = Visibility.Visible;
            }
            else if (waiting > 0)
            {
                AlertFixButton.Content = "Try again";
                AlertFixButton.Visibility = Visibility.Visible;
            }
            else
            {
                AlertFixButton.Visibility = Visibility.Collapsed;
            }
        }

        // The button on the alert problem bar ("Go to Outlook", "Allow sending", "Try again").
        private async void AlertFix_Click(object sender, RoutedEventArgs e)
        {
            string action = AlertFixButton.Content as string;
            if (action == "Go to Outlook")
            {
                NavOutlook.IsChecked = true;
                return;
            }
            AlertFixButton.IsEnabled = false;
            try
            {
                if (action == "Allow sending" && outlook != null)
                {
                    AlertProblemText.Text = "Finish in your web browser: Microsoft asks whether ScamFilter may send email for you.";
                    CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
                    try
                    {
                        await outlook.RequestSendPermissionAsync(timeout.Token);
                        Activate();
                    }
                    finally
                    {
                        timeout.Dispose();
                    }
                }
                await alerts.FlushAsync();
            }
            catch (Exception ex)
            {
                alerts.Problem = OutlookAccount.Explain(ex);
            }
            finally
            {
                AlertFixButton.IsEnabled = true;
                ShowAlertState();
            }
        }

        // ------------------------------------------------------------------
        // Alerts: what triggers them
        // ------------------------------------------------------------------

        // Notes a protection change for the alert. While unlocked, notes are collected and sent
        // as one alert when it locks; otherwise the alert goes out right away.
        private void NoteChange(string change)
        {
            pendingChanges.Add(change);
            if (!IsUnlocked)
            {
                SendPendingChanges();   // made without an unlock window (a reset, say): send now
            }
        }

        // Sends the collected change notes as one alert.
        private void SendPendingChanges()
        {
            if (pendingChanges.Count == 0 || alerts == null)
            {
                return;
            }
            alerts.Raise(AlertComposer.ProtectionChanged(account.Name, new List<string>(pendingChanges), false));
            pendingChanges.Clear();
        }

        // An Unsafe verdict: alert about it (once per message), if that's turned on.
        private void AlertAboutUnsafe(MessageRecord r, Verdict v, string key, string where, DateTime whenLocal)
        {
            if (alerts == null || !alerts.Settings.OnUnsafe || alerts.Settings.Contacts.Count == 0)
            {
                return;
            }
            AlertComposer.Flagged f = new AlertComposer.Flagged();
            string address = MetadataFeatures.EmailAddress(r.Sender);
            f.From = r.DisplayName.Trim().Length > 0 ? r.DisplayName.Trim() + " <" + (address.Length > 0 ? address : r.Sender) + ">" : r.Sender.Trim();
            f.Subject = r.Subject.Trim().Length > 0 ? r.Subject.Trim() : r.Preview(80);
            f.WhenLocal = whenLocal;
            f.Where = where;
            f.Key = key;
            foreach (string reason in FriendlyReasons(v))
            {
                if (f.Reasons.Count < 3)
                {
                    f.Reasons.Add(reason);
                }
            }
            alerts.Raise(AlertComposer.Unsafe(account.Name, new List<AlertComposer.Flagged> { f }));
        }

        // What makes a hand-checked message "the same message" for alerts: its text.
        private static string ContentKey(MessageRecord r)
        {
            string text = (r.Sender + "\n" + r.FullText()).Trim().ToLowerInvariant();
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).Substring(0, 24);
        }

        // ------------------------------------------------------------------
        // The tripwire (see ProtectionFingerprint)
        // ------------------------------------------------------------------

        private void RememberFingerprint()
        {
            account.ProtectionFingerprint = ProtectionFingerprint.Compute(AccountStore.FolderOf(account));
            try
            {
                AccountStore.Save(store);
            }
            catch (IOException)
            {
                // saved next time
            }
        }

        // At start-up: were the protection files changed by something other than ScamFilter?
        private void CheckForOutsideChanges()
        {
            string now = ProtectionFingerprint.Compute(AccountStore.FolderOf(account));
            List<string> differences = ProtectionFingerprint.Differences(account.ProtectionFingerprint, now);
            if (differences.Count > 0 && alerts.Settings.OnProtectionChange)
            {
                alerts.Raise(AlertComposer.ProtectionChanged(account.Name, differences, true));
            }
            if (account.ProtectionFingerprint != now)
            {
                RememberFingerprint();
            }
        }
    }
}
