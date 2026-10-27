using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace ScamFilter.Desktop
{
    /*
     * Runs once when the app starts, before any window opens. In order:
     *   1. set up the data folder (and the built-in model)
     *   2. pick the account: the one used last opens straight away (checking messages never
     *      needs a password); with no accounts yet, the welcome window makes one; with several
     *      and no record of the last one, the person chooses and proves it's them
     *   3. open the main window for that account
     *
     * Several copies can run at once (open ScamFilter again for a second window). They share the
     * data folder, and the shared files are written in a way that's safe for that: see
     * SharedFiles.cs in ScamFilter.Core.
     *
     * Command-line options:
     *   --developer   open the developer environment straight away (see below)
     *   --self-test   check the window itself, off-screen (see MainWindow.SelfTest.cs)
     *
     * THE DEVELOPER ENVIRONMENT (for the person building ScamFilter)
     * Pressing Ctrl+Shift+D while the account window is open (or starting with --developer)
     * opens ScamFilter without an account. It looks exactly like the normal app, plus the
     * developer tabs: Outlook (linking an Outlook account and checking its mail, see ShowOutlook
     * below), the AI viewer (what the model learned and why it scored a message the way it did),
     * the Model page (train it and read the report), and the Developer page (the Outlook app
     * registration, the data folder, and a reset button).
     *
     * Why it's safe to leave in: the developer environment runs in its own data folder,
     * %LOCALAPPDATA%\ScamFilter\Developer, with its own model, lists, and Outlook sign-in. Nothing
     * done there can switch off a real account's protections or change the model real accounts
     * use. Someone talked into opening it gets an empty sandbox, not your settings. That's also
     * why it needs no password: there's nothing in it to protect.
     */
    public partial class App : Application
    {
        // True while the developer environment is open (see the class comment).
        public static bool DeveloperMode = false;

        /*
         * Whether the Outlook features show: the Outlook page, "Use my Microsoft account" when
         * making an account, the Microsoft row on the Account page, and the alerts on the
         * Protections page (alerts are emailed through the linked Outlook, so without Outlook
         * they have no way to go out).
         *
         * For now they're developer-only: they show in the developer environment and are hidden
         * from everyone else. To give them back to everyone, make this return true.
         */
        public static bool ShowOutlook
        {
            get { return DeveloperMode; }
        }

        // Where the real accounts' data lives, and where the developer environment's lives.
        public static string NormalDataFolder = "";
        public static string DeveloperDataFolder = "";   // %LOCALAPPDATA%\ScamFilter\Developer

        private bool selfTest = false;        // started with --self-test?
        private string selfTestFolder = "";   // %TEMP%\ScamFilterSelfTest, where the test writes

        // Runs first, before any window: reads the command line, sets up the data folder, and
        // opens the right window (see the class comment).
        protected override void OnStartup(StartupEventArgs e)
        {
            foreach (string arg in e.Args)
            {
                if (arg == "--self-test")
                {
                    selfTest = true;
                }
                if (arg == "--developer")
                {
                    DeveloperMode = true;
                }
            }
            // Windows are opened by hand below; the app ends when the main window closes.
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            // Any error nobody caught shows a message instead of silently closing the app.
            // (Set up first, so even a problem during startup is reported.)
            DispatcherUnhandledException += OnUnhandledException;
            TaskScheduler.UnobservedTaskException += (s, args) => args.SetObserved();

            // Old Windows text encodings (code page 1252), used to repair badly decoded pastes.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // Keep all data in %LOCALAPPDATA%\ScamFilter (for example C:\Users\you\AppData\Local\ScamFilter),
            // so the .exe works from anywhere: Downloads, the desktop, a USB stick.
            NormalDataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ScamFilter");
            DeveloperDataFolder = Path.Combine(NormalDataFolder, "Developer");
            Paths.BaseDir = NormalDataFolder;
            if (selfTest)
            {
                // A throwaway data folder, so the test can't touch your own data or sign-in.
                selfTestFolder = Path.Combine(Path.GetTempPath(), "ScamFilterSelfTest");
                Paths.BaseDir = Path.Combine(selfTestFolder, "data");
                try
                {
                    if (Directory.Exists(Paths.BaseDir))
                    {
                        Directory.Delete(Paths.BaseDir, true);   // start from a fresh install every time
                    }
                    File.Delete(Path.Combine(selfTestFolder, "result.txt"));
                }
                catch (Exception)
                {
                    // a leftover file still in use; the test still works
                }
                Directory.CreateDirectory(selfTestFolder);
            }
            try
            {
                Paths.EnsureDefaultData();
            }
            catch (Exception ex)
            {
                MessageBox.Show("ScamFilter couldn't set up its data folder:\n\n" + Paths.DataFolder + "\n\n" + ex.Message,
                    "ScamFilter", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            base.OnStartup(e);
            if (selfTest)
            {
                StartSelfTest();
                return;
            }
            if (DeveloperMode)
            {
                OpenDeveloperEnvironment();
                return;
            }

            AccountStore.Store store;
            try
            {
                store = AccountStore.Load();
            }
            catch (Exception ex)
            {
                MessageBox.Show("ScamFilter couldn't read its accounts file:\n\n" + AccountStore.FilePath + "\n\n" + ex.Message,
                    "ScamFilter", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
                return;
            }
            Account account = store.Find(store.LastUsedId);
            if (account == null && store.Accounts.Count == 1)
            {
                account = store.Accounts[0];
            }
            if (account == null)
            {
                AccountWindow.Mode mode = store.Accounts.Count == 0 ? AccountWindow.Mode.FirstRun : AccountWindow.Mode.Pick;
                AccountWindow first = new AccountWindow(null, store, OutlookAppConfig.Load(), mode, null);
                if (first.ShowDialog() != true)
                {
                    Shutdown(0);
                    return;
                }
                if (first.DeveloperRequested)
                {
                    OpenDeveloperEnvironment();
                    return;
                }
                if (first.Chosen == null)
                {
                    Shutdown(0);
                    return;
                }
                account = first.Chosen;
            }
            OpenMainWindow(store, account);
        }

        // Opens the main window for an account (and remembers it as the one to open next time).
        private void OpenMainWindow(AccountStore.Store store, Account account)
        {
            store.LastUsedId = account.Id;
            AccountStore.Save(store);
            MainWindow window = new MainWindow(store, account);
            MainWindow = window;
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            window.Show();
        }

        /*
         * Opens the developer environment: switches every file path to the developer data
         * folder (Paths.BaseDir), sets that folder up like a fresh install, and opens the main
         * window with its one account, "Developer", which has no password.
         */
        private void OpenDeveloperEnvironment()
        {
            DeveloperMode = true;
            Paths.BaseDir = DeveloperDataFolder;
            AccountStore.Store store;
            Account account;
            try
            {
                Paths.EnsureDefaultData();
                store = AccountStore.Load();
                account = store.Accounts.Count > 0 ? store.Accounts[0] : null;
                if (account == null)
                {
                    account = new Account();
                    account.Id = Guid.NewGuid().ToString("N");
                    account.Name = "Developer";
                    store.Accounts.Add(account);
                    AccountSetup.Initialize(account, false);
                    AccountStore.Save(store);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("ScamFilter couldn't set up the developer environment in:\n\n" + DeveloperDataFolder + "\n\n" + ex.Message,
                    "ScamFilter", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
                return;
            }
            OpenMainWindow(store, account);
        }

        // Starts a fresh copy of ScamFilter (normal, or straight into the developer environment)
        // and closes this one. Used to leave or reset the developer environment.
        public static void Restart(bool developer)
        {
            string exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe))
            {
                System.Diagnostics.ProcessStartInfo info = new System.Diagnostics.ProcessStartInfo(exe);
                if (developer)
                {
                    info.ArgumentList.Add("--developer");
                }
                info.UseShellExecute = false;
                System.Diagnostics.Process started = System.Diagnostics.Process.Start(info);
                if (started != null)
                {
                    started.Dispose();
                }
            }
            Current.Shutdown(0);
        }

        // --self-test: makes a test account in a throwaway folder and runs the window's self-test
        // off-screen (see MainWindow.SelfTest.cs). The exit code is 0 when everything passed.
        private void StartSelfTest()
        {
            // A test account, made the way the welcome window makes one.
            AccountStore.Store store = AccountStore.Load();
            string code;
            Account account = AccountStore.Create(store, "Self-test", ScamFilter.Desktop.MainWindow.SelfTestPassword, out code);
            AccountSetup.Initialize(account, false);
            AccountStore.Save(store);
            MainWindow window = new MainWindow(store, account);
            MainWindow = window;
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            window.ShowInTaskbar = false;
            window.ShowActivated = false;
            window.WindowStartupLocation = WindowStartupLocation.Manual;
            window.Left = -30000;   // off every screen
            window.Top = -30000;
            window.Loaded += async (s, args) =>
            {
                // Give the window's own start-up work a moment to finish first.
                await Task.Delay(1500);
                string report;
                int code;
                try
                {
                    report = await window.RunSelfTestAsync();
                    code = window.SelfTestFailures == 0 ? 0 : 1;
                }
                catch (Exception ex)
                {
                    report = "FAIL  the self-test itself crashed: " + ex;
                    code = 2;
                }
                WriteSelfTestResult(report);
                Shutdown(code);   // also closes the window
            };
            window.Show();
        }

        // Writes the self-test report where the installer looks for it.
        private void WriteSelfTestResult(string text)
        {
            try
            {
                File.WriteAllText(Path.Combine(selfTestFolder, "result.txt"), text);
            }
            catch (IOException)
            {
                // nowhere to write; the exit code still says pass or fail
            }
        }

        /*
         * The app is shutting down: its main window was closed, or Shutdown was called. End the
         * process right here, so nothing left over can keep ScamFilter running invisibly after
         * its window is gone: a model retraining in the background, an Outlook sign-in still
         * waiting for the browser, a dialog. That's safe: the files ScamFilter replaces (the
         * model, lists, settings) are written to a temporary file first and swapped in whole
         * (SharedFiles.WriteAtomically, ScamModel.Save), a marked result is saved the moment it's
         * clicked, and Windows lets go of the lock files when the process ends. A retraining cut
         * short simply runs again the next time ScamFilter opens.
         */
        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);
            Environment.Exit(e.ApplicationExitCode);
        }

        // Any error the code didn't catch: shown in a message box, and the app keeps running.
        private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            if (selfTest)
            {
                // No message boxes during a self-test: write the error down and stop.
                WriteSelfTestResult("FAIL  unhandled error: " + e.Exception);
                e.Handled = true;
                Shutdown(3);
                return;
            }
            MessageBox.Show("Something went wrong:\n\n" + e.Exception.Message
                + "\n\nScamFilter will keep running.", "ScamFilter", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}
