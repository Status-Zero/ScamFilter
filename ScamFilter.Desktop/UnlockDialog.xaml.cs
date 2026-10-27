using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace ScamFilter.Desktop
{
    /*
     * The "prove it's you" dialog. ShowDialog() returns true once the person has unlocked the
     * account by any of three ways:
     *   - its password
     *   - signing in again to its linked Microsoft account
     *   - its recovery code, which also sets a new password (and makes a new recovery code)
     *
     * Wrong passwords are counted by AccountStore.CheckPassword. On the 5th wrong try in a row,
     * the account locks for a while and onLockedOut runs (MainWindow uses it to send an alert).
     * Checking a password takes a fraction of a second on purpose (see PasswordHasher), so it
     * runs off the window's thread.
     */
    public partial class UnlockDialog : Window
    {
        private readonly AccountStore.Store store;
        private readonly Account account;
        private readonly Func<Task<OutlookAccount>> getOutlook;
        private readonly Action<Account, int, int> onLockedOut;
        private CancellationTokenSource microsoftCancel = null;

        // A new recovery code made while resetting the password; the caller shows it.
        public string NewRecoveryCode = "";

        public UnlockDialog(Window owner, AccountStore.Store store, Account account, string heading, string purpose,
                            Func<Task<OutlookAccount>> getOutlook, Action<Account, int, int> onLockedOut)
        {
            InitializeComponent();
            Owner = owner;
            if (owner == null || !owner.IsVisible)
            {
                WindowStartupLocation = WindowStartupLocation.CenterScreen;
            }
            this.store = store;
            this.account = account;
            this.getOutlook = getOutlook;
            this.onLockedOut = onLockedOut;
            Heading.Text = heading;
            PurposeText.Text = purpose;
            UseMicrosoftLink.Visibility = account.HasMicrosoft && getOutlook != null ? Visibility.Visible : Visibility.Collapsed;
            ForgotLink.Visibility = account.RecoveryHash.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
            UsePasswordLink.Visibility = account.HasPassword ? Visibility.Visible : Visibility.Collapsed;
            MicrosoftText.Text = "Sign in to " + account.MicrosoftUser + " in your web browser. Microsoft asks for the "
                + "password even if it remembers you, so this proves it's really you.";
            if (!account.HasPassword)
            {
                ShowPanel(MicrosoftPanel);
            }
            Loaded += (s, e) =>
            {
                if (PasswordPanel.Visibility == Visibility.Visible)
                {
                    PasswordInput.Focus();
                }
                ShowLockState();
            };
            Closed += (s, e) =>
            {
                if (microsoftCancel != null)
                {
                    microsoftCancel.Cancel();
                }
            };
        }

        // Shows one of the three ways to unlock (password, Microsoft, recovery code) and hides the others.
        private void ShowPanel(FrameworkElement panel)
        {
            PasswordPanel.Visibility = panel == PasswordPanel ? Visibility.Visible : Visibility.Collapsed;
            MicrosoftPanel.Visibility = panel == MicrosoftPanel ? Visibility.Visible : Visibility.Collapsed;
            RecoveryPanel.Visibility = panel == RecoveryPanel ? Visibility.Visible : Visibility.Collapsed;
        }

        // While locked out, say for how long, and don't accept anything.
        private bool ShowLockState()
        {
            TimeSpan left = account.LockedUntilUtc - DateTime.UtcNow;
            if (left <= TimeSpan.Zero)
            {
                return false;
            }
            int minutes = (int) Math.Ceiling(left.TotalMinutes);
            string text = "Too many wrong tries. Try again in " + minutes + (minutes == 1 ? " minute." : " minutes.");
            PasswordStatus.Text = text;
            RecoveryStatus.Text = text;
            return true;
        }

        // Typing clears the last message ("Wrong password").
        private void PasswordInput_KeyDown(object sender, KeyEventArgs e)
        {
            PasswordStatus.Text = "";
        }

        // "Unlock": checks the password (counting wrong tries; 5 in a row lock it for a while).
        private async void Unlock_Click(object sender, RoutedEventArgs e)
        {
            // Another ScamFilter window may have counted wrong tries too: start from its count.
            AccountStore.Refresh(store, account);
            if (ShowLockState())
            {
                return;
            }
            string typed = PasswordInput.Password;
            if (typed.Length == 0)
            {
                PasswordStatus.Text = "Type your password.";
                return;
            }
            UnlockButton.IsEnabled = false;
            PasswordStatus.Text = "Checking...";
            AccountStore.CheckResult result = await Task.Run(() => AccountStore.CheckPassword(account, typed, DateTime.UtcNow));
            AccountStore.Save(store);
            UnlockButton.IsEnabled = true;
            if (result == AccountStore.CheckResult.Correct)
            {
                DialogResult = true;
                return;
            }
            PasswordInput.Clear();
            PasswordInput.Focus();
            if (result == AccountStore.CheckResult.Wrong)
            {
                int left = AccountStore.AttemptsLeft(account);
                PasswordStatus.Text = "That's not the password. " + left + (left == 1 ? " try" : " tries") + " left before ScamFilter locks for a while.";
                return;
            }
            if (result == AccountStore.CheckResult.JustLockedOut && onLockedOut != null)
            {
                onLockedOut(account, account.FailedAttempts, (int) Math.Round((account.LockedUntilUtc - DateTime.UtcNow).TotalMinutes));
            }
            ShowLockState();
        }

        // "Use my Microsoft account instead".
        private void UseMicrosoft_Click(object sender, RoutedEventArgs e)
        {
            ShowPanel(MicrosoftPanel);
        }

        // "Use my password instead".
        private void UsePassword_Click(object sender, RoutedEventArgs e)
        {
            ShowPanel(PasswordPanel);
            PasswordInput.Focus();
        }

        // "Sign in with Microsoft": unlocks when the same Microsoft account that's linked signs in.
        private async void Microsoft_Click(object sender, RoutedEventArgs e)
        {
            if (getOutlook == null || microsoftCancel != null)
            {
                return;
            }
            MicrosoftButton.IsEnabled = false;
            MicrosoftStatus.Foreground = (System.Windows.Media.Brush) FindResource("TextSecondaryBrush");
            MicrosoftStatus.Text = "Finish signing in in your web browser...";
            microsoftCancel = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            try
            {
                OutlookAccount outlook = await getOutlook();
                bool same = await outlook.VerifyAsync(account.MicrosoftHomeId, account.MicrosoftUser, microsoftCancel.Token);
                Activate();
                if (same)
                {
                    account.FailedAttempts = 0;
                    account.LockedUntilUtc = DateTime.MinValue;
                    AccountStore.Save(store);
                    DialogResult = true;
                    return;
                }
                MicrosoftStatus.Foreground = (System.Windows.Media.Brush) FindResource("UnsafeBrush");
                MicrosoftStatus.Text = "That was a different Microsoft account. Sign in as " + account.MicrosoftUser + ".";
            }
            catch (Exception ex)
            {
                if (IsLoaded)
                {
                    MicrosoftStatus.Foreground = (System.Windows.Media.Brush) FindResource("UnsafeBrush");
                    MicrosoftStatus.Text = OutlookAccount.Explain(ex);
                }
            }
            finally
            {
                if (microsoftCancel != null)
                {
                    microsoftCancel.Dispose();
                    microsoftCancel = null;
                }
                MicrosoftButton.IsEnabled = true;
            }
        }

        // "Forgot your password?": shows the recovery code panel.
        private void Forgot_Click(object sender, RoutedEventArgs e)
        {
            ShowPanel(RecoveryPanel);
            RecoveryInput.Focus();
            ShowLockState();
        }

        // "Back" from the recovery code panel.
        private void BackToPassword_Click(object sender, RoutedEventArgs e)
        {
            ShowPanel(PasswordPanel);
            PasswordInput.Focus();
        }

        // "Reset password": checks the recovery code, sets the new password, and makes a new
        // recovery code (the used one stops working).
        private async void Reset_Click(object sender, RoutedEventArgs e)
        {
            if (ShowLockState())
            {
                return;
            }
            string code = RecoveryInput.Text;
            string password = NewPassword.Password;
            if (PasswordHasher.CleanRecoveryCode(code).Length != 16)
            {
                RecoveryStatus.Text = "The recovery code has 16 letters and numbers.";
                return;
            }
            string problem = PasswordHasher.WhyNotAllowed(password, account.Name);
            if (problem != null)
            {
                RecoveryStatus.Text = problem;
                return;
            }
            if (password != NewPasswordAgain.Password)
            {
                RecoveryStatus.Text = "The two passwords don't match.";
                return;
            }
            ResetButton.IsEnabled = false;
            RecoveryStatus.Text = "Checking...";
            AccountStore.Refresh(store, account);   // (wrong tries in other windows count too)
            AccountStore.CheckResult result = await Task.Run(() => AccountStore.CheckRecoveryCode(account, code, DateTime.UtcNow));
            if (result == AccountStore.CheckResult.Correct)
            {
                await Task.Run(() =>
                {
                    AccountStore.SetPassword(account, password);
                    NewRecoveryCode = AccountStore.NewRecoveryCode(account);   // the old code is used up
                });
                AccountStore.Save(store);
                DialogResult = true;
                return;
            }
            AccountStore.Save(store);
            ResetButton.IsEnabled = true;
            if (result == AccountStore.CheckResult.JustLockedOut && onLockedOut != null)
            {
                onLockedOut(account, account.FailedAttempts, (int) Math.Round((account.LockedUntilUtc - DateTime.UtcNow).TotalMinutes));
            }
            if (!ShowLockState())
            {
                RecoveryStatus.Text = "That recovery code isn't right. Check it and try again.";
            }
        }

        // "Cancel".
        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
}
