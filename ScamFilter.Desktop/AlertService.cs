using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ScamFilter.Desktop
{
    /*
     * Sends one account's alerts by email, through that account's linked Outlook.
     *
     *   Raise(alert)    decides whether this kind of alert is turned on, fixes who gets it
     *                   (the contacts right now), puts it in the waiting line, and tries to send
     *   FlushAsync()    sends what's waiting, oldest first, at most AlertLog.MaxPerHour an hour
     *
     * Anything that can't go out yet (no internet, Outlook not linked, sending not allowed yet)
     * stays waiting in alerts_waiting.jsonl and is tried again later: every few minutes while
     * the app is open, and the next time it starts. Problem says what's in the way, in words the
     * Protections page can show.
     */
    public class AlertService
    {
        private readonly Account account;
        private readonly string folder;
        private readonly Func<Task<OutlookAccount>> getOutlook;
        private bool sending = false;

        public AlertSettings Settings;   // who gets alerts, and for what
        public AlertLog Log;             // what was sent, and what's waiting
        public string Problem = "";      // why alerts can't go out right now, in plain words ("" if they can)

        // Runs (on the window's thread) after each send attempt, so the page can update.
        public event Action Changed;

        public AlertService(Account account, Func<Task<OutlookAccount>> getOutlook)
        {
            this.account = account;
            this.getOutlook = getOutlook;
            folder = AccountStore.FolderOf(account);
            Settings = AlertSettings.Load(folder);
            Log = new AlertLog(folder);
        }

        // Reads the settings again: another window with the same account may have changed them.
        public void ReloadSettings()
        {
            Settings = AlertSettings.Load(folder);
        }

        // Is this kind of alert turned on? (Test alerts always are.)
        public bool IsOn(AlertKind kind)
        {
            if (kind == AlertKind.Unsafe)
            {
                return Settings.OnUnsafe;
            }
            if (kind == AlertKind.WrongPassword)
            {
                return Settings.OnWrongPassword;
            }
            if (kind == AlertKind.ProtectionChange)
            {
                return Settings.OnProtectionChange;
            }
            return true;
        }

        // Queues an alert for the current contacts (if that kind is on) and tries to send it.
        public void Raise(Alert alert)
        {
            ReloadSettings();
            if (!IsOn(alert.Kind) || Settings.Contacts.Count == 0)
            {
                return;
            }
            alert.Recipients.Clear();
            foreach (AlertContact c in Settings.Contacts)
            {
                alert.Recipients.Add(new AlertContact { Name = c.Name, Email = c.Email });
            }
            Log.Queue(alert);
            _ = FlushAsync();
        }

        // Sends the waiting alerts (see the class comment). Safe to call any time: it does nothing
        // if there's nothing to send, or if another window is already sending.
        public async Task FlushAsync()
        {
            if (sending)
            {
                return;
            }
            // Only one window sends at a time. If another window with this account is sending
            // right now, it sends what's waiting, so this one leaves it to it.
            FileLock sendingLock = FileLock.TryAcquire(Path.Combine(folder, "alerts_sending.lock"));
            if (sendingLock == null)
            {
                return;
            }
            sending = true;
            try
            {
                Log.DropStale(DateTime.UtcNow);
                List<Alert> waiting = new List<Alert>(Log.Waiting);
                if (waiting.Count == 0)
                {
                    Problem = "";
                    return;
                }
                OutlookAccount outlook = await getOutlook();
                if (outlook == null || !outlook.IsSignedIn)
                {
                    Problem = "Alerts are sent from your Outlook account, and it isn't linked right now. Link it on the Outlook page.";
                    return;
                }
                GraphMailClient graph = new GraphMailClient(outlook.GetTokenAsync);
                foreach (Alert alert in waiting)
                {
                    Log.Reload();
                    if (Log.AlreadySent(alert.DedupeKey) || !Log.IsWaiting(alert.DedupeKey))
                    {
                        continue;   // another window sent it meanwhile
                    }
                    if (Log.SentLastHour(DateTime.UtcNow) >= AlertLog.MaxPerHour)
                    {
                        Problem = "Holding back some alerts: no more than " + AlertLog.MaxPerHour + " go out in an hour.";
                        return;
                    }
                    CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromMinutes(1));
                    try
                    {
                        foreach (AlertContact to in alert.Recipients)
                        {
                            string body = alert.Body.Replace("{contact}", to.Name.Length > 0 ? to.Name : "there");
                            await graph.SendMailAsync(to.Email, alert.Subject, body, outlook.GetSendTokenAsync, timeout.Token);
                        }
                        Log.MarkSent(alert, DateTime.UtcNow);
                        Problem = "";
                    }
                    finally
                    {
                        timeout.Dispose();
                    }
                }
            }
            catch (SendPermissionRequiredException)
            {
                Problem = "ScamFilter needs your OK to send alert emails from your Outlook account.";
            }
            catch (SignInRequiredException)
            {
                Problem = "Your Outlook sign-in has expired, so alerts can't be sent. Sign in again on the Outlook page.";
            }
            catch (HttpRequestException)
            {
                Problem = "No internet connection right now. Alerts will go out once it's back.";
            }
            catch (OperationCanceledException)
            {
                Problem = "Outlook took too long to answer. Alerts will be tried again in a few minutes.";
            }
            catch (GraphException ex)
            {
                Problem = "Outlook didn't send the alert: " + ex.Message;
            }
            catch (Exception ex)
            {
                Problem = "Couldn't send alerts: " + ex.Message;
            }
            finally
            {
                sending = false;
                sendingLock.Release();
                Action handler = Changed;
                if (handler != null)
                {
                    handler();
                }
            }
        }

        // The account's name, for alert text.
        public string Name
        {
            get { return account.Name; }
        }
    }

    /*
     * Setting up and removing an account's folder.
     *
     * A new account starts with empty lists and alerts with no contacts. The FIRST account made
     * after updating from version 1.2 takes over what 1.2 had: its Blocked and Trusted lists,
     * its Outlook sign-in, and the automatic-check setting, so nothing is lost.
     */
    public static class AccountSetup
    {
        // Makes a new account's folder: empty lists, default alert settings, Outlook settings. With
        // takeOverOldData, the first account inherits what version 1.2 had (see above).
        public static void Initialize(Account a, bool takeOverOldData)
        {
            string folder = AccountStore.FolderOf(a);
            Directory.CreateDirectory(folder);
            List<ListEntry> blocked = takeOverOldData ? ProtectionLists.Load(Paths.DataFile("blocklist.txt")) : new List<ListEntry>();
            List<ListEntry> trusted = takeOverOldData ? ProtectionLists.Load(Paths.DataFile("whitelist.txt")) : new List<ListEntry>();
            ProtectionLists.Save(Path.Combine(folder, "blocklist.txt"), blocked, true);
            ProtectionLists.Save(Path.Combine(folder, "whitelist.txt"), trusted, false);
            if (!File.Exists(AlertSettings.PathFor(folder)))
            {
                new AlertSettings().Save(folder);
            }
            AccountOutlookSettings outlook = new AccountOutlookSettings();
            if (takeOverOldData)
            {
                outlook.AutoCheck = OutlookAppConfig.LegacyAutoCheck();
                try
                {
                    OutlookAccount.MoveLegacySignIn(folder);
                }
                catch (IOException)
                {
                    // in use or unreadable: signing in again fixes it
                }
            }
            outlook.Save(folder);
            a.ProtectionFingerprint = ProtectionFingerprint.Compute(folder);
        }

        // Deletes an account's folder (its lists, sign-in, and alert settings).
        public static void DeleteFolder(Account a)
        {
            string folder = AccountStore.FolderOf(a);
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, true);
            }
        }

        /*
         * The alert for 5 wrong passwords, sent from outside the main window (the account picker
         * at start-up). Uses the account's own Outlook sign-in, if it has one.
         */
        public static void SendLockoutAlert(Account a, OutlookAppConfig config, int attempts, int minutes)
        {
            AlertService alerts = new AlertService(a, async () =>
            {
                if (!config.IsConfigured)
                {
                    return null;
                }
                OutlookAccount outlook = await OutlookAccount.CreateAsync(config, AccountStore.FolderOf(a));
                await outlook.ResumeAsync(a.MicrosoftHomeId, CancellationToken.None);
                return outlook;
            });
            alerts.Raise(AlertComposer.WrongPassword(a.Name, attempts, minutes, DateTime.Now));
        }
    }
}
