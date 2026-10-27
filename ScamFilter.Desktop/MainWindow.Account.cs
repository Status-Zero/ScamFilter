using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace ScamFilter.Desktop
{
    /*
     * The Account page: the open account's name, password, recovery code, and Microsoft link,
     * plus switching, adding, and removing accounts. Every change here needs the password
     * (RequireUnlockAsync), and the security ones are reported to alert contacts.
     */
    public partial class MainWindow
    {
        // Fills in the Account page: name, password, recovery code and Microsoft link.
        private void RefreshAccountPage()
        {
            AccountPageName.Text = account.Name;
            if (account.HasPassword)
            {
                AccountPagePassword.Text = "Set";
                ChangePasswordButton.Content = "Change password";
            }
            else
            {
                AccountPagePassword.Text = App.DeveloperMode ? "None: the developer environment doesn't use one"
                    : "None: this account opens with Microsoft";
                ChangePasswordButton.Content = "Set a password";
            }
            AccountPageRecovery.Text = account.RecoveryHash.Length > 0 ? "Saved when the password was made"
                : (account.HasPassword ? "None yet" : App.DeveloperMode ? "Not needed" : "Not needed: Microsoft handles account recovery");
            NewCodeButton.Visibility = account.HasPassword ? Visibility.Visible : Visibility.Collapsed;
            if (account.HasMicrosoft)
            {
                AccountPageMicrosoft.Text = account.MicrosoftUser;
                MicrosoftAccountButton.Content = "Unlink";
            }
            else
            {
                AccountPageMicrosoft.Text = "Not linked";
                MicrosoftAccountButton.Content = "Link on the Outlook page";
            }
            // (The Microsoft row is hidden when the Outlook features are, see ShowOrHideOutlookFeatures.)
        }

        // "Rename" (asks for the password first, and tells alert contacts).
        private async void RenameAccount_Click(object sender, RoutedEventArgs e)
        {
            if (!await RequireUnlockAsync("Rename this account", "Account changes ask for your password."))
            {
                return;
            }
            InputDialog dialog = InputDialog.ForText(this, "Rename account", "Name", account.Name,
                name => AccountStore.WhyNameNotAllowed(store, name, account));
            if (dialog.ShowDialog() != true || dialog.Value == account.Name)
            {
                return;
            }
            string old = account.Name;
            account.Name = dialog.Value;
            AccountStore.Save(store);
            AccountNameText.Text = account.Name;
            AccountInitial.Text = account.Name.Substring(0, 1).ToUpperInvariant();
            RefreshAccountPage();
            NoteChange("The account was renamed from " + old + " to " + account.Name);
        }

        // "Change password" (or "Set a password" for an account that opens with Microsoft).
        // A new password gets a new recovery code, shown once.
        private async void ChangePassword_Click(object sender, RoutedEventArgs e)
        {
            bool hadPassword = account.HasPassword;
            if (!await RequireUnlockAsync(hadPassword ? "Change your password" : "Set a password",
                    hadPassword ? "Type your current password first." : "Confirm it's you with Microsoft first."))
            {
                return;
            }
            InputDialog dialog = InputDialog.ForNewPassword(this, hadPassword ? "New password" : "Set a password",
                hadPassword ? "" : "With a password, this account can also be unlocked without Microsoft (when you're offline, say).",
                p => PasswordHasher.WhyNotAllowed(p, account.Name));
            if (dialog.ShowDialog() != true)
            {
                return;
            }
            string password = dialog.Value;
            string code = "";
            await Task.Run(() =>
            {
                AccountStore.SetPassword(account, password);
                code = AccountStore.NewRecoveryCode(account);   // a new password gets a new recovery code
            });
            AccountStore.Save(store);
            new CodeDialog(this, code).ShowDialog();
            RefreshAccountPage();
            AccountStatus.Text = hadPassword ? "Password changed." : "Password set.";
            NoteChange(hadPassword ? "The password was changed" : "A password was added to the account");
        }

        // "Make a new recovery code": the old one stops working.
        private async void NewRecoveryCode_Click(object sender, RoutedEventArgs e)
        {
            if (!await RequireUnlockAsync("Make a new recovery code", "The old code stops working. Type your password first."))
            {
                return;
            }
            string code = await Task.Run(() => AccountStore.NewRecoveryCode(account));
            AccountStore.Save(store);
            new CodeDialog(this, code).ShowDialog();
            RefreshAccountPage();
            NoteChange("A new recovery code was made (the old one no longer works)");
        }

        // "Unlink" the Microsoft account, or, when none is linked, go to the Outlook page to link one.
        private async void MicrosoftAccountButton_Click(object sender, RoutedEventArgs e)
        {
            if (!account.HasMicrosoft)
            {
                NavOutlook.IsChecked = true;   // linking happens by signing in there
                return;
            }
            await UnlinkMicrosoftAsync();
            RefreshAccountPage();
        }

        // ------------------------------------------------------------------
        // Switching, adding, and removing accounts
        // ------------------------------------------------------------------

        private void SwitchAccount_Click(object sender, RoutedEventArgs e)
        {
            if (App.DeveloperMode)
            {
                // The real accounts live in another data folder; a fresh start opens them.
                MessageBoxResult answer = MessageBox.Show(this, "Leave the developer environment and go back to the normal accounts?",
                    "Switch account", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);
                if (answer == MessageBoxResult.Yes)
                {
                    App.Restart(false);
                }
                return;
            }
            AccountWindow picker = new AccountWindow(this, store, appConfig, AccountWindow.Mode.Pick, account);
            if (picker.ShowDialog() != true)
            {
                return;
            }
            if (picker.DeveloperRequested)
            {
                EnterDeveloperEnvironment();
            }
            else if (picker.Chosen != null && picker.Chosen != account)
            {
                OpenAccount(picker.Chosen);
            }
        }

        // "Add an account": opens the account window to make another account, then opens it.
        private void AddAccount_Click(object sender, RoutedEventArgs e)
        {
            AccountWindow maker = new AccountWindow(this, store, appConfig, AccountWindow.Mode.Add, account);
            if (maker.ShowDialog() != true)
            {
                return;
            }
            if (maker.DeveloperRequested)
            {
                EnterDeveloperEnvironment();
            }
            else if (maker.Chosen != null)
            {
                OpenAccount(maker.Chosen);
            }
        }

        // Ctrl+Shift+D in the account window: lock up, then start again in the developer environment.
        private void EnterDeveloperEnvironment()
        {
            LockProtections();
            App.Restart(true);
        }

        // Replaces this window with one for another account.
        private void OpenAccount(Account other)
        {
            LockProtections();
            store.LastUsedId = other.Id;
            AccountStore.Save(store);
            MainWindow next = new MainWindow(store, other);
            next.WindowState = WindowState;
            Application.Current.MainWindow = next;
            next.Show();
            Close();
        }

        // "Remove this account": deletes its folder (lists, sign-in, alerts) after telling its alert
        // contacts, then shows the account window so someone else can choose.
        private async void RemoveAccount_Click(object sender, RoutedEventArgs e)
        {
            if (App.DeveloperMode)
            {
                MessageBox.Show(this, "The developer environment's account can't be removed on its own. To start over, use "
                    + "Reset developer environment on the Developer page.", "Remove account", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (!await RequireUnlockAsync("Remove " + account.Name + "'s account?", "Removing an account asks for its password."))
            {
                return;
            }
            string whatGoes = App.ShowOutlook
                ? "Its blocked and trusted lists, alert contacts, and Outlook link are deleted. Nothing in the Outlook mailbox itself changes."
                : "Its blocked and trusted lists are deleted.";
            MessageBoxResult answer = MessageBox.Show(this,
                "Remove " + account.Name + "'s account from this PC?\n\n" + whatGoes,
                "Remove account", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes)
            {
                return;
            }
            // Tell the alert contacts first: after this, there's no account to send from.
            NoteChange(account.Name + "'s ScamFilter account was removed from the computer");
            SendPendingChanges();
            await alerts.FlushAsync();
            if (outlook != null)
            {
                try
                {
                    await outlook.SignOutAsync();
                }
                catch (Exception)
                {
                    // the sign-in file is deleted with the folder anyway
                }
            }
            // Nothing may write into the folder once it's being deleted.
            foreach (DispatcherTimer timer in new DispatcherTimer[] { outlookTimer, lockTimer, alertRetryTimer, trainingTimer })
            {
                if (timer != null)
                {
                    timer.Stop();
                }
            }
            store.Accounts.Remove(account);
            if (store.LastUsedId == account.Id)
            {
                store.LastUsedId = "";
            }
            AccountStore.Save(store);
            try
            {
                AccountSetup.DeleteFolder(account);
            }
            catch (IOException)
            {
                // a file still open; the folder is no longer used by anything
            }
            catch (UnauthorizedAccessException)
            {
                // same
            }

            // Next: another account, or a new one.
            AccountWindow next = store.Accounts.Count > 0
                ? new AccountWindow(null, store, appConfig, AccountWindow.Mode.Pick, null)
                : new AccountWindow(null, store, appConfig, AccountWindow.Mode.FirstRun, null);
            Hide();
            if (next.ShowDialog() == true && next.Chosen != null)
            {
                MainWindow window = new MainWindow(store, next.Chosen);
                Application.Current.MainWindow = window;
                window.Show();
                Close();
            }
            else
            {
                Application.Current.Shutdown();
            }
        }
    }
}
