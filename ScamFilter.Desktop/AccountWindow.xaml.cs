using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace ScamFilter.Desktop
{
    /*
     * Three ways this window opens (see Mode):
     *   FirstRun   no accounts yet: make one (a password, or Microsoft instead where the
     *              Outlook features show, see App.ShowOutlook)
     *   Add        "Add an account" from the Account page
     *   Pick       "Switch account", or at start-up when it isn't clear whose turn it is:
     *              choose an account, then prove it's you (UnlockDialog)
     * When it closes with DialogResult = true, Chosen is the account to open, or
     * DeveloperRequested is true: Ctrl+Shift+D was pressed to open the developer environment
     * (no account; see App.OpenDeveloperEnvironment).
     */
    public partial class AccountWindow : Window
    {
        // Why the window was opened (see the class comment).
        public enum Mode { FirstRun, Add, Pick }

        // One row of the account list.
        public class Row
        {
            public string Initial { get; set; }    // the circle with the first letter
            public string Name { get; set; }       // the account's name
            public string Detail { get; set; }     // "Opens with: Password", ...
            public Account Account { get; set; }   // the account itself
        }

        private readonly AccountStore.Store store;
        private readonly OutlookAppConfig config;
        private readonly Account current;
        private readonly Mode startMode;
        private CancellationTokenSource microsoftCancel = null;

        // The account to open when the window closes with DialogResult = true (null otherwise).
        public Account Chosen = null;

        // Ctrl+Shift+D was pressed: open the developer environment instead of an account.
        public bool DeveloperRequested = false;

        public AccountWindow(Window owner, AccountStore.Store store, OutlookAppConfig config, Mode mode, Account current)
        {
            InitializeComponent();
            if (owner != null && owner.IsVisible)
            {
                Owner = owner;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                ShowInTaskbar = false;
            }
            this.store = store;
            this.config = config;
            this.current = current;
            startMode = mode;
            // Microsoft sign-in is one of the Outlook features, which are developer-only for now.
            MicrosoftOption.Visibility = config.IsConfigured && App.ShowOutlook ? Visibility.Visible : Visibility.Collapsed;
            if (!App.ShowOutlook)
            {
                PickIntro.Text = "Choose your account. ScamFilter asks for its password to open it.";
                CreateIntro.Text = "Each person on this PC gets their own ScamFilter account, with their own blocked and trusted "
                    + "lists. Checking messages never needs a password. Changing protections does, so nobody can talk you "
                    + "into turning them off.";
            }
            PickCancelButton.Visibility = current != null ? Visibility.Visible : Visibility.Collapsed;
            if (mode == Mode.Pick)
            {
                ShowPick();
            }
            else
            {
                ShowCreate();
            }
            PreviewKeyDown += AccountWindow_PreviewKeyDown;
            Closed += (s, e) =>
            {
                if (microsoftCancel != null)
                {
                    microsoftCancel.Cancel();
                }
            };
        }

        /*
         * The developer keybind: Ctrl+Shift+D opens ScamFilter without an account, in the
         * developer environment (same screens plus the developer tabs). It's deliberately not
         * shown anywhere on screen. The developer environment keeps its own data folder, so
         * nothing done in it can change a real account's protections or the shared model.
         */
        private void AccountWindow_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            ModifierKeys both = ModifierKeys.Control | ModifierKeys.Shift;
            if (e.Key == Key.D && (Keyboard.Modifiers & both) == both && microsoftCancel == null)
            {
                e.Handled = true;
                RequestDeveloper();
            }
        }

        // What Ctrl+Shift+D does: close the window, asking for the developer environment.
        internal void RequestDeveloper()
        {
            DeveloperRequested = true;
            Chosen = null;
            DialogResult = true;
        }

        // Shows the list of accounts to choose from.
        private void ShowPick()
        {
            Heading.Text = current == null ? "Who's using ScamFilter?" : "Switch account";
            List<Row> rows = new List<Row>();
            foreach (Account a in store.Accounts)
            {
                Row row = new Row();
                row.Name = a.Name + (a == current ? " (open now)" : "");
                row.Initial = a.Name.Length > 0 ? a.Name.Substring(0, 1).ToUpperInvariant() : "?";
                row.Detail = "Opens with: " + a.SignInDescription;
                row.Account = a;
                rows.Add(row);
            }
            AccountList.ItemsSource = rows;
            PickPanel.Visibility = Visibility.Visible;
            CreatePanel.Visibility = Visibility.Collapsed;
        }

        // Shows the "make an account" form.
        private void ShowCreate()
        {
            Heading.Text = startMode == Mode.FirstRun ? "Welcome to ScamFilter" : "Add an account";
            CreateIntro.Visibility = Visibility.Visible;
            BackToPickButton.Visibility = startMode == Mode.FirstRun ? Visibility.Collapsed : Visibility.Visible;
            BackToPickButton.Content = startMode == Mode.Pick ? "Back" : "Cancel";
            PickPanel.Visibility = Visibility.Collapsed;
            CreatePanel.Visibility = Visibility.Visible;
            Dispatcher.BeginInvoke(new Action(() => NameInput.Focus()), System.Windows.Threading.DispatcherPriority.Input);
        }

        // "Add an account" under the list.
        private void ShowCreate_Click(object sender, RoutedEventArgs e)
        {
            ShowCreate();
        }

        // "Back" (to the list) or "Cancel", depending on how the window was opened.
        private void BackToPick_Click(object sender, RoutedEventArgs e)
        {
            if (startMode == Mode.Pick)
            {
                ShowPick();
            }
            else
            {
                DialogResult = false;
            }
        }

        // "Cancel" under the list: close without choosing.
        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }

        // ------------------------------------------------------------------
        // Choosing an account
        // ------------------------------------------------------------------

        private void AccountList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            Row row = AccountList.SelectedItem as Row;
            AccountList.SelectedItem = null;
            if (row == null)
            {
                return;
            }
            if (row.Account == current)
            {
                DialogResult = false;   // already open
                return;
            }
            UnlockDialog unlock = new UnlockDialog(this, store, row.Account, "Open " + row.Account.Name + "'s account",
                "Prove it's you to open this account.", MicrosoftFor(row.Account), LockedOut);
            if (unlock.ShowDialog() == true)
            {
                if (unlock.NewRecoveryCode.Length > 0)
                {
                    new CodeDialog(this, unlock.NewRecoveryCode).ShowDialog();
                }
                Choose(row.Account);
            }
        }

        // A way to reach an account's linked Microsoft sign-in (for "use my Microsoft account").
        private Func<Task<OutlookAccount>> MicrosoftFor(Account a)
        {
            if (!a.HasMicrosoft || !config.IsConfigured)
            {
                return null;
            }
            return () => OutlookAccount.CreateAsync(config, AccountStore.FolderOf(a));
        }

        // 5 wrong passwords in a row while picking an account: send the lockout alert.
        private void LockedOut(Account a, int attempts, int minutes)
        {
            AccountSetup.SendLockoutAlert(a, config, attempts, minutes);
        }

        // Closes the window with this account chosen, and remembers it for next time.
        private void Choose(Account a)
        {
            Chosen = a;
            store.LastUsedId = a.Id;
            AccountStore.Save(store);
            DialogResult = true;
        }

        // ------------------------------------------------------------------
        // Making an account
        // ------------------------------------------------------------------

        private void PasswordAgain_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                Create_Click(sender, null);
            }
        }

        // "Create account": checks the name and password, makes the account (hashing the password
        // takes a moment, so it runs off the window's thread), then shows the recovery code once.
        private async void Create_Click(object sender, RoutedEventArgs e)
        {
            string name = NameInput.Text.Trim();
            string problem = AccountStore.WhyNameNotAllowed(store, name, null);
            if (problem == null)
            {
                problem = PasswordHasher.WhyNotAllowed(PasswordInput.Password, name);
            }
            if (problem == null && PasswordInput.Password != PasswordAgain.Password)
            {
                problem = "The two passwords don't match.";
            }
            if (problem != null)
            {
                CreateStatus.Text = problem;
                return;
            }
            CreateButton.IsEnabled = false;
            CreateStatus.Text = "";
            string password = PasswordInput.Password;
            bool firstAccount = store.Accounts.Count == 0;
            string code = "";
            Account made = null;
            try
            {
                made = await Task.Run(() =>
                {
                    Account a = AccountStore.Create(store, name, password, out code);
                    AccountSetup.Initialize(a, firstAccount);
                    return a;
                });
                AccountStore.Save(store);
            }
            catch (Exception ex)
            {
                if (made != null)
                {
                    store.Accounts.Remove(made);
                }
                CreateStatus.Text = "Couldn't make the account: " + ex.Message;
                CreateButton.IsEnabled = true;
                return;
            }
            new CodeDialog(this, code).ShowDialog();
            Choose(made);
        }

        // "Use my Microsoft account instead": signs in with Microsoft in the browser and makes an
        // account that opens with that sign-in instead of a password.
        private async void CreateWithMicrosoft_Click(object sender, RoutedEventArgs e)
        {
            if (microsoftCancel != null || !config.IsConfigured)
            {
                return;
            }
            MicrosoftButton.IsEnabled = false;
            CreateButton.IsEnabled = false;
            MicrosoftStatus.Foreground = (System.Windows.Media.Brush) FindResource("TextSecondaryBrush");
            MicrosoftStatus.Text = "Finish signing in in your web browser...";
            microsoftCancel = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            bool firstAccount = store.Accounts.Count == 0;
            Account a = new Account();
            a.Id = Guid.NewGuid().ToString("N");
            bool kept = false;
            try
            {
                OutlookAccount outlook = await OutlookAccount.CreateAsync(config, AccountStore.FolderOf(a));
                await outlook.SignInAsync(microsoftCancel.Token);
                Activate();
                foreach (Account other in store.Accounts)
                {
                    if (other.MicrosoftHomeId == outlook.HomeId)
                    {
                        MicrosoftStatus.Foreground = (System.Windows.Media.Brush) FindResource("UnsafeBrush");
                        MicrosoftStatus.Text = outlook.UserName + " already has a ScamFilter account: " + other.Name + ".";
                        return;
                    }
                }
                string name = NameInput.Text.Trim();
                if (name.Length == 0)
                {
                    name = await new GraphMailClient(outlook.GetTokenAsync).GetDisplayNameAsync(microsoftCancel.Token);
                }
                if (name.Length == 0)
                {
                    name = outlook.UserName.Split('@')[0];
                }
                string unique = name.Length > 40 ? name.Substring(0, 40) : name;
                for (int n = 2; AccountStore.WhyNameNotAllowed(store, unique, null) != null && n < 100; n++)
                {
                    unique = name + " " + n;
                }
                a.Name = unique;
                a.MicrosoftHomeId = outlook.HomeId;
                a.MicrosoftUser = outlook.UserName;
                AccountSetup.Initialize(a, firstAccount);
                store.Accounts.Add(a);
                AccountStore.Save(store);
                kept = true;
                Choose(a);
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
                if (!kept)
                {
                    try
                    {
                        AccountSetup.DeleteFolder(a);   // the half-made account's sign-in file
                    }
                    catch (Exception)
                    {
                        // still in use; it's harmless and unused
                    }
                }
                if (microsoftCancel != null)
                {
                    microsoftCancel.Dispose();
                    microsoftCancel = null;
                }
                if (IsLoaded)
                {
                    MicrosoftButton.IsEnabled = true;
                    CreateButton.IsEnabled = true;
                }
            }
        }
    }
}
