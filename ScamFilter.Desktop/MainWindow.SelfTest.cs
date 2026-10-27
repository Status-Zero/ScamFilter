using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using UglyToad.PdfPig.Core;
using UglyToad.PdfPig.Fonts.Standard14Fonts;
using UglyToad.PdfPig.Writer;
using ComTypes = System.Runtime.InteropServices.ComTypes;

namespace ScamFilter.Desktop
{
    /*
     * A built-in check of the window itself, run with:   ScamFilter.exe --self-test
     *
     * WPF only finds some mistakes while the program runs (a style that can't be applied, a
     * missing resource, a template part with the wrong name), so this opens the real window
     * off-screen, visits every page, puts each into its different states, and checks that
     * everything drew without errors. It also MEASURES the hint-text fix: in every empty text
     * box, the hint's first letter must sit exactly where the blinking cursor is, before and
     * after the box gets keyboard focus.
     *
     * It also tries every way a picture gets in, end to end, with Windows' real OCR: pasting a
     * screenshot (copied the way Win+Shift+S and the Print Screen key copy one), uploading each
     * picture format, a sideways phone photo, and a PDF with a text page, a link, and a scanned
     * page. The test picture is drawn by the test itself, with a known sentence in it. And it
     * drops an email the way the new Outlook hands one over (see FakeNewOutlookDrag).
     *
     * It uses a temporary data folder, so your own data, lists, and Outlook sign-in aren't touched.
     * The paste test borrows the clipboard and puts your copied text back afterwards (it skips
     * itself if you have a picture or files copied, so those aren't lost).
     * The results go to %TEMP%\ScamFilterSelfTest\result.txt (see App.xaml.cs).
     */
    public partial class MainWindow
    {
        // The test account's password (App.StartSelfTest makes the account).
        internal const string SelfTestPassword = "self test password 1";

        // The report being written, and how many checks failed so far.
        private readonly StringBuilder selfTestLog = new StringBuilder();
        private int selfTestFailures = 0;

        // Records one check: "ok" or "FAIL", with a detail that helps find the problem.
        private void Expect(string name, bool ok, string detail)
        {
            selfTestLog.AppendLine((ok ? "ok    " : "FAIL  ") + name + (detail.Length > 0 ? "   [" + detail + "]" : ""));
            if (!ok)
            {
                selfTestFailures++;
            }
        }

        // Lets WPF finish drawing (layout, templates, queued work) before looking at the result.
        private static void LetWpfCatchUp()
        {
            DispatcherFrame frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,
                new DispatcherOperationCallback(f => { ((DispatcherFrame) f).Continue = false; return null; }), frame);
            Dispatcher.PushFrame(frame);
        }

        // Returns the report; `failures` is how many checks failed.
        internal async Task<string> RunSelfTestAsync()
        {
            selfTestLog.AppendLine("ScamFilter self-test, " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            await Step("Check page: check a message", async () =>
            {
                NavCheck.IsChecked = true;
                BodyBox.Text = "USPS: Your package is on hold due to an unpaid fee of $1.99. Pay now at usps-redelivery.top/track";
                SenderBox.Text = "+44 7700 900123";
                await CheckCurrentAsync();
                LetWpfCatchUp();
                Expect("verdict shown", ResultView.Visibility == Visibility.Visible && VerdictTitle.Text.Length > 0,
                    VerdictTitle.Text + " / " + CheckStatus.Text);
                Expect("added to history", history.Count == 1, history.Count.ToString());
            });
            await Step("Check page: email fields, import bar, Outlook link", () =>
            {
                TypeEmail.IsChecked = true;
                ShowImportBar("Self-test note.");
                SetCheckPageOutlookLink("https://outlook.live.com/owa/?ItemID=test");
                LetWpfCatchUp();
                Expect("email fields visible", EmailFields.Visibility == Visibility.Visible, "");
                Expect("Open in Outlook shown", OpenInOutlookText.Visibility == Visibility.Visible, "");
                SetCheckPageOutlookLink("https://evil.top/owa");
                Expect("non-Outlook link refused", OpenInOutlookText.Visibility == Visibility.Collapsed, "");
                ClearButton_Click(this, null);
                LetWpfCatchUp();
                return Task.CompletedTask;
            });
            await Step("Text boxes: hint lines up with the cursor", () =>
            {
                NavCheck.IsChecked = true;
                TypeEmail.IsChecked = true;
                LetWpfCatchUp();
                foreach (TextBox box in new TextBox[] { SenderBox, NameBox, BodyBox })
                {
                    CheckHintAlignment(box, false);
                    Keyboard.Focus(box);
                    LetWpfCatchUp();
                    CheckHintAlignment(box, true);
                }
                TypeText.IsChecked = true;
                return Task.CompletedTask;
            });
            await Step("Outlook features: developer environment only", () =>
            {
                bool shown = App.ShowOutlook;
                Expect("Outlook tab hidden (it's a developer tab)", DeveloperNav.Visibility == (shown ? Visibility.Visible : Visibility.Collapsed), "");
                Expect("no Link Outlook tip on the Check page", LinkOutlookTip.Visibility == (shown ? Visibility.Visible : Visibility.Collapsed), "");
                Expect("no alerts on the Protections page", AlertsPanel.Visibility == (shown ? Visibility.Visible : Visibility.Collapsed), "");
                Expect("no Microsoft row on the Account page", MicrosoftRowLabel.Visibility == (shown ? Visibility.Visible : Visibility.Collapsed)
                    && MicrosoftAccountButton.Visibility == (shown ? Visibility.Visible : Visibility.Collapsed), "");
                Expect("never signed in to Microsoft", shown || outlook == null, "");
                return Task.CompletedTask;
            });
            await PictureSteps();
            await Step("Outlook page: no app registration in this build", () =>
            {
                // The page is a developer tab; show the tabs just to check it draws.
                DeveloperNav.Visibility = Visibility.Visible;
                NavOutlook.IsChecked = true;
                LetWpfCatchUp();
                bool expected = appConfig.IsConfigured ? OutlookSignInPanel.Visibility == Visibility.Visible
                    : OutlookUnavailablePanel.Visibility == Visibility.Visible;
                Expect("the right panel shows", expected, appConfig.IsConfigured ? "configured" : "not configured");
                Expect("developer setup not on this page", !OutlookSetupPanel.IsVisible, "");
                return Task.CompletedTask;
            });
            await Step("Outlook page: list with a checked email", () =>
            {
                GraphMailClient.MailItem mail = new GraphMailClient.MailItem();
                mail.Id = "self-test";
                mail.FromName = "Netflix";
                mail.FromAddress = "billing@netflix-account.top";
                mail.Subject = "Your account is on hold";
                mail.Received = DateTimeOffset.Now;
                mail.IsRead = false;
                MessageRecord r = new MessageRecord();
                r.Type = "email";
                r.Sender = mail.FromAddress;
                r.DisplayName = mail.FromName;
                r.Subject = mail.Subject;
                r.BodyText = "Update your payment details within 24 hours or your membership will be cancelled.";
                mail.Record = r;
                outlookItems.Add(MakeOutlookItem(mail, ScamDetector.Check(r)));
                UpdateOutlookBadge();
                OutlookToolbar.Visibility = Visibility.Visible;
                OutlookListArea.Visibility = Visibility.Visible;
                OutlookUnavailablePanel.Visibility = Visibility.Collapsed;
                LetWpfCatchUp();
                Expect("row drawn", OutlookList.Items.Count == 1 && OutlookList.ItemContainerGenerator.ContainerFromIndex(0) != null, "");
                OutlookCountBox.IsDropDownOpen = true;
                LetWpfCatchUp();
                Expect("drop-down list opens", OutlookCountBox.IsDropDownOpen, "");
                OutlookCountBox.IsDropDownOpen = false;
                outlookItems.Clear();
                UpdateOutlookBadge();
                UpdateOutlookView();
                SetUpDeveloperPages();   // hides the developer tabs again outside the developer environment
                return Task.CompletedTask;
            });
            await Step("History page", () =>
            {
                NavHistory.IsChecked = true;
                LetWpfCatchUp();
                Expect("history list shown", HistoryList.Visibility == Visibility.Visible, "");
                return Task.CompletedTask;
            });
            await Step("Protections page: locked, and the rules", () =>
            {
                NavLists.IsChecked = true;
                LetWpfCatchUp();
                Expect("starts locked", !IsUnlocked && LockText.Text == "Locked", LockText.Text);
                string refused = AddToBlocked("gmail.com", "");
                Expect("blocking gmail.com refused, with a reason", refused.Contains("everyone"), refused);
                string blocked = AddToBlocked("https://pay.usps-redelivery.top/x", "toll scam");
                LetWpfCatchUp();
                Expect("blocking works without the password", blocked.StartsWith("Blocked usps-redelivery.top", StringComparison.Ordinal), blocked);
                Expect("row shown", BlockList.Items.Count == 1 && BlockEmpty.Visibility == Visibility.Collapsed, BlockList.Items.Count.ToString());
                foreach (TextBox box in new TextBox[] { BlockInput, BlockLabel, TrustInput })
                {
                    CheckHintAlignment(box, false);
                }
                if (App.ShowOutlook)
                {
                    CheckHintAlignment(ContactEmailInput, false);   // in the alerts section, which only shows with Outlook
                }
                return Task.CompletedTask;
            });
            await Step("Protections page: unlocked changes", async () =>
            {
                AccountStore.CheckResult check = await Task.Run(() => AccountStore.CheckPassword(account, SelfTestPassword, DateTime.UtcNow));
                Expect("the account's password checks out", check == AccountStore.CheckResult.Correct, check.ToString());
                unlockedUntilUtc = DateTime.UtcNow.AddMinutes(UnlockMinutes);   // as if typed into the dialog
                UpdateLockState();
                Expect("shows unlocked", LockText.Text.StartsWith("Unlocked", StringComparison.Ordinal), LockText.Text);
                string trusted = await AddToTrustedAsync("(404) 555-0101", "Mom");
                LetWpfCatchUp();
                Expect("trusting works once unlocked", trusted.StartsWith("Trusted", StringComparison.Ordinal), trusted);
                Expect("trusted row shown", TrustList.Items.Count == 1, TrustList.Items.Count.ToString());
                MessageRecord mom = new MessageRecord();
                mom.Type = "text";
                mom.Sender = "404-555-0101";
                mom.BodyText = "dinner at 6?";
                Expect("the detector uses the new trusted entry", ScamDetector.Check(mom).DecidedBy == "whitelist", "");
                ContactNameInput.Text = "Test Contact";
                ContactEmailInput.Text = "test.contact@example.com";
                AddContact_Click(this, null);
                await Task.Delay(300);
                LetWpfCatchUp();
                Expect("alert contact added", alerts.Settings.Contacts.Count == 1 && ContactList.Items.Count == 1, ContactStatus.Text);
                Expect("says Outlook isn't linked for alerts", AlertProblemBar.Visibility == Visibility.Visible, AlertProblemText.Text);
                LockProtections();
                LetWpfCatchUp();
                Expect("locks again", !IsUnlocked && LockText.Text == "Locked", LockText.Text);
                Expect("the change alert waits to be sent", alerts.Log.Waiting.Count >= 1, alerts.Log.Waiting.Count.ToString());
                Expect("the lists were fingerprinted", account.ProtectionFingerprint == ProtectionFingerprint.Compute(AccountStore.FolderOf(account)), "");
            });
            await Step("Account page", () =>
            {
                NavAccount.IsChecked = true;
                LetWpfCatchUp();
                Expect("name shown", AccountPageName.Text == account.Name, AccountPageName.Text);
                Expect("password shown as set", AccountPagePassword.Text == "Set", AccountPagePassword.Text);
                Expect("nav shows the account", AccountNameText.Text == account.Name, AccountNameText.Text);
                return Task.CompletedTask;
            });
            await Step("Dialogs draw", () =>
            {
                UnlockDialog unlock = new UnlockDialog(this, store, account, "Unlock", "Self-test.", null, null);
                unlock.ShowActivated = false;
                unlock.Left = -30000;
                unlock.WindowStartupLocation = WindowStartupLocation.Manual;
                unlock.Show();
                LetWpfCatchUp();
                Expect("unlock dialog", unlock.PasswordInput.Template != null && unlock.PasswordInput.ActualHeight > 20,
                    unlock.PasswordInput.ActualHeight.ToString("0"));
                unlock.Close();
                CodeDialog code = new CodeDialog(this, "ABCD-EFGH-JKMN-PQRS");
                code.ShowActivated = false;
                code.Left = -30000;
                code.WindowStartupLocation = WindowStartupLocation.Manual;
                code.Show();
                LetWpfCatchUp();
                Expect("recovery code dialog", code.ActualHeight > 100, code.ActualHeight.ToString("0"));
                code.SavedBox.IsChecked = true;   // (otherwise closing asks first)
                code.Close();
                AccountWindow picker = new AccountWindow(null, store, appConfig, AccountWindow.Mode.Add, account);
                picker.ShowActivated = false;
                picker.Left = -30000;
                picker.WindowStartupLocation = WindowStartupLocation.Manual;
                picker.Show();
                LetWpfCatchUp();
                Expect("account window", picker.CreatePanel.Visibility == Visibility.Visible && picker.ActualHeight > 200, picker.ActualHeight.ToString("0"));
                picker.Close();
                InputDialog input = InputDialog.ForNewPassword(this, "New password", "", p => null);
                input.ShowActivated = false;
                input.Left = -30000;
                input.WindowStartupLocation = WindowStartupLocation.Manual;
                input.Show();
                LetWpfCatchUp();
                Expect("password dialog", input.ActualHeight > 100, input.ActualHeight.ToString("0"));
                input.Close();
                return Task.CompletedTask;
            });
            await Step("Developer tabs: hidden outside the developer environment", () =>
            {
                Expect("developer tabs hidden", DeveloperNav.Visibility == (App.DeveloperMode ? Visibility.Visible : Visibility.Collapsed), "");
                return Task.CompletedTask;
            });
            await Step("Developer tabs: the pages draw", () =>
            {
                // Shown just for this check, then hidden again.
                DeveloperNav.Visibility = Visibility.Visible;
                NavAiViewer.IsChecked = true;
                LetWpfCatchUp();
                Expect("AI viewer shown", PageAiViewer.Visibility == Visibility.Visible && PageAiViewer.ActualHeight > 200,
                    PageAiViewer.ActualHeight.ToString("0"));
                Expect("model summary filled in", AiModelSummary.Text.StartsWith("Logistic regression", StringComparison.Ordinal), AiModelSummary.Text);
                AiLookupBox.Text = "verify";
                LetWpfCatchUp();
                Expect("word lookup finds features", AiLookupResults.Text.Contains("verify"), AiLookupResults.Text.Length.ToString());
                AiTopScam_Click(this, null);
                Expect("strongest scam words listed", AiLookupResults.Text.Split('\n').Length > 20, "");
                if (lastRecord != null && lastVerdict != null)
                {
                    string breakdown = ScoringBreakdown(lastRecord, lastVerdict);
                    Expect("scoring breakdown adds up", breakdown.Contains("THE SCORE") && breakdown.Contains("P(scam)"), "");
                }
                NavDeveloper.IsChecked = true;
                LetWpfCatchUp();
                Expect("Developer page shown", PageDeveloper.Visibility == Visibility.Visible && OutlookSetupPanel.ActualHeight > 100,
                    OutlookSetupPanel.ActualHeight.ToString("0"));
                if (ClientIdBox.Text.Length == 0)
                {
                    CheckHintAlignment(ClientIdBox, false);
                }
                NavModel.IsChecked = true;
                LetWpfCatchUp();
                Expect("Model page shown", PageModel.Visibility == Visibility.Visible, "");
                DeveloperNav.Visibility = Visibility.Collapsed;
                NavCheck.IsChecked = true;
                LetWpfCatchUp();
                return Task.CompletedTask;
            });
            await Step("Account window: the developer keybind's result", () =>
            {
                AccountWindow window = new AccountWindow(null, store, appConfig, AccountWindow.Mode.FirstRun, null);
                window.ShowActivated = false;
                window.ShowInTaskbar = false;
                window.Left = -30000;
                window.WindowStartupLocation = WindowStartupLocation.Manual;
                // What Ctrl+Shift+D does, once the window is up. (Real key presses can't be faked
                // here: WPF reads Ctrl and Shift from the actual keyboard.)
                window.Loaded += (s, e) => window.Dispatcher.BeginInvoke(new Action(() => window.RequestDeveloper()));
                bool? result = window.ShowDialog();
                Expect("opens the developer environment, no account", result == true && window.DeveloperRequested && window.Chosen == null, "");
                return Task.CompletedTask;
            });
            NavCheck.IsChecked = true;
            selfTestLog.AppendLine(selfTestFailures == 0 ? "ALL PASSED" : selfTestFailures + " FAILED");
            return selfTestLog.ToString();
        }

        internal int SelfTestFailures
        {
            get { return selfTestFailures; }
        }

        // ------------------------------------------------------------------
        // Pictures and PDFs: pasting, uploading, OCR
        // ------------------------------------------------------------------

        // The sentence in the test picture, and a word from it that OCR must find.
        private const string TestPictureLine1 = "USPS: Your package is on hold.";
        private const string TestPictureLine2 = "Pay the $1.99 fee at usps-redelivery.top today.";
        private const string TestPictureWord = "package";

        private async Task PictureSteps()
        {
            byte[] png = TestPicturePng();
            await Step("Pasting a screenshot into the message box", async () =>
            {
                if (ClipboardHelper.HasImage() || ClipboardHelper.HasFiles())
                {
                    selfTestLog.AppendLine("skip  a picture or files are copied right now; not replacing them");
                    return;
                }
                string saved = ClipboardHelper.GetText();
                try
                {
                    // 1. Only a PNG on the clipboard: how Win+Shift+S and the Snipping Tool copy a screenshot.
                    DataObject copied = new DataObject();
                    copied.SetData("PNG", new MemoryStream(png));
                    Clipboard.SetDataObject(copied, true);
                    NavCheck.IsChecked = true;
                    ClearButton_Click(this, null);   // an empty form, and no result showing
                    Keyboard.Focus(BodyBox);
                    LetWpfCatchUp();
                    Expect("Paste is allowed with only a picture copied", ApplicationCommands.Paste.CanExecute(null, BodyBox), "");
                    ApplicationCommands.Paste.Execute(null, BodyBox);
                    string read = await WaitForCheckedMessageAsync();
                    Expect("the screenshot's text was read and checked", ReadsTestPicture(read) && ResultView.Visibility == Visibility.Visible,
                        Shorten(read) + " / " + CheckStatus.Text);
                    Expect("marked as text read from a picture", importedRecord != null && importedRecord.IsOcr(), "");

                    // 2. Only a Bitmap: how the Print Screen key and older programs copy one.
                    Clipboard.SetImage(DecodeTestPicture(png));
                    ClearButton_Click(this, null);
                    ApplicationCommands.Paste.Execute(null, BodyBox);
                    read = await WaitForCheckedMessageAsync();
                    Expect("a Print Screen bitmap was read", ReadsTestPicture(read), Shorten(read) + " / " + CheckStatus.Text);
                }
                finally
                {
                    try
                    {
                        if (saved != null)
                        {
                            Clipboard.SetText(saved);
                        }
                        else
                        {
                            Clipboard.Clear();
                        }
                    }
                    catch (Exception)
                    {
                        // the clipboard is busy; nothing more to do
                    }
                    ClearForm();
                }
            });

            string folder = Path.Combine(Path.GetTempPath(), "ScamFilterSelfTest", "uploads");
            await Step("Uploading pictures", async () =>
            {
                Directory.CreateDirectory(folder);
                BitmapSource picture = DecodeTestPicture(png);
                Dictionary<string, BitmapEncoder> formats = new Dictionary<string, BitmapEncoder>();
                formats[".png"] = new PngBitmapEncoder();
                formats[".jpg"] = new JpegBitmapEncoder();
                formats[".bmp"] = new BmpBitmapEncoder();
                formats[".gif"] = new GifBitmapEncoder();
                formats[".tif"] = new TiffBitmapEncoder();
                foreach (KeyValuePair<string, BitmapEncoder> format in formats)
                {
                    string path = Path.Combine(folder, "message" + format.Key);
                    SavePicture(format.Value, BitmapFrame.Create(picture), path);
                    await OpenFileAsync(path);
                    Expect(format.Key + " read", ReadsTestPicture(BodyBox.Text), Shorten(BodyBox.Text) + " / " + CheckStatus.Text);
                }

                // A phone photo stored sideways, with an EXIF note saying "turn me 90 degrees clockwise".
                BitmapSource sideways = new TransformedBitmap(picture, new RotateTransform(270));
                BitmapMetadata note = new BitmapMetadata("jpg");
                note.SetQuery("/app1/ifd/{ushort=274}", (ushort) 6);
                string photo = Path.Combine(folder, "phone photo.jpg");
                SavePicture(new JpegBitmapEncoder(), BitmapFrame.Create(sideways, null, note, null), photo);
                await OpenFileAsync(photo);
                Expect("a sideways phone photo is turned upright", ReadsTestPicture(BodyBox.Text), Shorten(BodyBox.Text) + " / " + CheckStatus.Text);

                // A picture saved with no extension at all
                string bare = Path.Combine(folder, "screenshot");
                File.WriteAllBytes(bare, png);
                await OpenFileAsync(bare);
                Expect("a picture with no extension is recognized", ReadsTestPicture(BodyBox.Text), Shorten(BodyBox.Text) + " / " + CheckStatus.Text);
            });

            await Step("Uploading a PDF (a text page with a link, and a scanned page)", async () =>
            {
                Directory.CreateDirectory(folder);
                PdfDocumentBuilder builder = new PdfDocumentBuilder();
                PdfDocumentBuilder.AddedFont font = builder.AddStandard14Font(Standard14Font.Helvetica);
                PdfPageBuilder textPage = builder.AddPage(UglyToad.PdfPig.Content.PageSize.Letter);
                textPage.AddText("Geek Squad: your plan renewed for $399.99.", 12, new PdfPoint(60, 700), font);
                textPage.AddText("Cancel at www.bestbuy.com/cancel within 24 hours.", 12, new PdfPoint(60, 680), font);
                textPage.AddLink("https://geek-billing-cancel.top/refund", new PdfRectangle(60, 676, 360, 692));
                PdfPageBuilder scannedPage = builder.AddPage(UglyToad.PdfPig.Content.PageSize.Letter);
                scannedPage.AddPng(png, new PdfRectangle(60, 560, 552, 680));
                string pdf = Path.Combine(folder, "invoice.pdf");
                File.WriteAllBytes(pdf, builder.Build());
                await OpenFileAsync(pdf);
                Expect("the text page's text, exactly", BodyBox.Text.Contains("renewed for $399.99"), Shorten(BodyBox.Text) + " / " + CheckStatus.Text);
                Expect("the link's real target kept", importedRecord != null
                    && importedRecord.Urls.Any(u => u.Href.Contains("geek-billing-cancel.top")), "");
                Expect("the scanned page read with OCR", importedRecord != null && ReadsTestPicture(importedRecord.ImageText),
                    importedRecord == null ? "" : Shorten(importedRecord.ImageText));
                Expect("checked", ResultView.Visibility == Visibility.Visible && VerdictTitle.Text.Length > 0, VerdictTitle.Text);
                ClearForm();
            });
            await Step("Dragging an email out of the new Outlook", async () =>
            {
                Directory.CreateDirectory(folder);
                string email = Path.Combine(folder, "Your account has been limited.eml");
                File.WriteAllText(email,
                    "From: \"PayPal\" <service@paypa1-support.com>\r\n"
                    + "To: you@example.com\r\n"
                    + "Subject: Your account has been limited\r\n"
                    + "Date: Mon, 26 Oct 2026 08:00:00 -0500\r\n"
                    + "MIME-Version: 1.0\r\n"
                    + "Content-Type: text/plain; charset=utf-8\r\n\r\n"
                    + "We noticed unusual activity on your account. Confirm your identity within 24 hours at "
                    + "https://paypa1-support.com/verify or your account will be closed.\r\n");

                FakeNewOutlookDrag plain = new FakeNewOutlookDrag(email, true);
                Expect("like the real one, it hands nothing over to a plain request",
                    new DataObject(plain).GetData(DataFormats.FileDrop) == null, "");

                FakeNewOutlookDrag drag = new FakeNewOutlookDrag(email, true);
                ClearButton_Click(this, null);
                await HandleDropAsync(new DataObject(drag));
                Expect("ScamFilter said it can wait, then said it's done", drag.Started && drag.Ended, "");
                Expect("Outlook's file is gone after the drop (ScamFilter kept its own copy)", !File.Exists(email), "");
                Expect("the email was read and checked", BodyBox.Text.Contains("unusual activity") && ResultView.Visibility == Visibility.Visible,
                    Shorten(BodyBox.Text) + " / " + CheckStatus.Text);
                Expect("its sender came along", SenderBox.Text.Contains("paypa1-support.com"), SenderBox.Text);

                // An older new Outlook: nothing usable at all. The drop explains what to do.
                FakeNewOutlookDrag old = new FakeNewOutlookDrag(email, false);
                DataObject oldData = new DataObject(old);
                Expect("an older new Outlook's drag is still accepted", IsDroppable(oldData), "");
                ClearButton_Click(this, null);
                await HandleDropAsync(oldData);
                Expect("and the drop says to save the email instead", CheckStatus.Text.Contains("Save as"), CheckStatus.Text);
                ClearButton_Click(this, null);
            });

            try
            {
                Directory.Delete(folder, true);
            }
            catch (Exception)
            {
                // a file still open; it's in the temporary folder anyway
            }
        }

        /*
         * Pretends to be an email dragged out of the new Outlook, which can't be dragged in for
         * real here. Like the real one, it offers a file (FileDrop) but only hands it over after
         * StartOperation (see AsyncDrop.cs), and it deletes the file at EndOperation, as a
         * source may. offersFile = false pretends to be an older new Outlook, which offers only
         * its own browser-engine format.
         *
         * It implements the same two COM interfaces the real one does. Here they're called
         * directly by .NET, with no COM in between, but the code under test can't tell.
         */
        private sealed class FakeNewOutlookDrag : ComTypes.IDataObject, AsyncDrop.IDataObjectAsyncCapability
        {
            private const short FileDropFormat = 15;                          // CF_HDROP, Windows' number for FileDrop
            private const int NoSuchFormat = unchecked((int) 0x80040064);     // DV_E_FORMATETC: "I don't have that"
            private const int NotImplemented = unchecked((int) 0x80004001);   // E_NOTIMPL

            private readonly string path;
            private readonly bool offersFile;
            private readonly short chromiumFormat = unchecked((short) DataFormats.GetDataFormat("Chromium Web Custom MIME Data Format").Id);

            public bool Started = false;   // StartOperation was called
            public bool Ended = false;     // EndOperation was called

            public FakeNewOutlookDrag(string path, bool offersFile)
            {
                this.path = path;
                this.offersFile = offersFile;
            }

            // ---- IDataObjectAsyncCapability ----

            public void SetAsyncMode(bool doAsync)
            {
            }

            public void GetAsyncMode(out bool isAsync)
            {
                isAsync = true;
            }

            public void StartOperation(IntPtr reserved)
            {
                Started = true;
            }

            public void InOperation(out bool inOperation)
            {
                inOperation = Started && !Ended;
            }

            // The drop is over: like a real source may, delete the file it handed over.
            public void EndOperation(int result, IntPtr reserved, uint effects)
            {
                Ended = true;
                File.Delete(path);
            }

            // ---- IDataObject ----

            // "Do you have this format?" 0 means yes.
            public int QueryGetData(ref ComTypes.FORMATETC format)
            {
                bool hglobal = (format.tymed & ComTypes.TYMED.TYMED_HGLOBAL) != 0;
                bool file = offersFile && format.cfFormat == FileDropFormat;
                return hglobal && (file || format.cfFormat == chromiumFormat) ? 0 : NoSuchFormat;
            }

            // The data itself: the file's path in a DROPFILES block, and only once the operation started.
            public void GetData(ref ComTypes.FORMATETC format, out ComTypes.STGMEDIUM medium)
            {
                if (QueryGetData(ref format) != 0 || format.cfFormat != FileDropFormat || !Started)
                {
                    throw new COMException("Not available.", NoSuchFormat);
                }
                medium = new ComTypes.STGMEDIUM();
                medium.tymed = ComTypes.TYMED.TYMED_HGLOBAL;
                medium.unionmember = DropFiles(path);
                medium.pUnkForRelease = null;
            }

            /*
             * Windows' DROPFILES block: a 20-byte header (where the names start, a point, two
             * flags; the last flag says the names are 2-byte Unicode), then each path ending in a
             * 0 character, then one more 0 to end the list.
             */
            private static IntPtr DropFiles(string file)
            {
                byte[] names = Encoding.Unicode.GetBytes(file + "\0\0");
                IntPtr block = Marshal.AllocHGlobal(20 + names.Length);
                Marshal.WriteInt32(block, 0, 20);      // the names start right after the header
                Marshal.WriteInt64(block, 4, 0);       // the drop point (unused)
                Marshal.WriteInt32(block, 12, 0);      // "point is in the non-client area" (no)
                Marshal.WriteInt32(block, 16, 1);      // Unicode names (yes)
                Marshal.Copy(names, 0, block + 20, names.Length);
                return block;
            }

            public void GetDataHere(ref ComTypes.FORMATETC format, ref ComTypes.STGMEDIUM medium)
            {
                throw new COMException("Not implemented.", NotImplemented);
            }

            public int GetCanonicalFormatEtc(ref ComTypes.FORMATETC formatIn, out ComTypes.FORMATETC formatOut)
            {
                formatOut = formatIn;
                return NotImplemented;
            }

            public void SetData(ref ComTypes.FORMATETC formatIn, ref ComTypes.STGMEDIUM medium, bool release)
            {
                throw new COMException("Not implemented.", NotImplemented);
            }

            public ComTypes.IEnumFORMATETC EnumFormatEtc(ComTypes.DATADIR direction)
            {
                throw new COMException("Not implemented.", NotImplemented);
            }

            public int DAdvise(ref ComTypes.FORMATETC format, ComTypes.ADVF advf, ComTypes.IAdviseSink sink, out int connection)
            {
                connection = 0;
                return NotImplemented;
            }

            public void DUnadvise(int connection)
            {
                throw new COMException("Not implemented.", NotImplemented);
            }

            public int EnumDAdvise(out ComTypes.IEnumSTATDATA enumAdvise)
            {
                enumAdvise = null;
                return NotImplemented;
            }
        }

        /*
         * Draws the test picture: two lines of dark text on white, like a cropped screenshot of a
         * text message, as PNG bytes.
         */
        private static byte[] TestPicturePng()
        {
            DrawingVisual visual = new DrawingVisual();
            DrawingContext dc = visual.RenderOpen();
            dc.DrawRectangle(Brushes.White, null, new Rect(0, 0, 820, 130));
            Typeface face = new Typeface("Segoe UI");
            string[] lines = { TestPictureLine1, TestPictureLine2 };
            for (int i = 0; i < lines.Length; i++)
            {
                FormattedText text = new FormattedText(lines[i], CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
                    face, 26, Brushes.Black, 1.0);
                dc.DrawText(text, new Point(24, 20 + i * 48));
            }
            dc.Close();
            RenderTargetBitmap bitmap = new RenderTargetBitmap(820, 130, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(visual);
            PngBitmapEncoder encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            MemoryStream bytes = new MemoryStream();
            encoder.Save(bytes);
            return bytes.ToArray();
        }

        // PNG bytes -> a picture.
        private static BitmapSource DecodeTestPicture(byte[] png)
        {
            BitmapDecoder decoder = BitmapDecoder.Create(new MemoryStream(png), BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            return decoder.Frames[0];
        }

        // Saves one picture in an encoder's format.
        private static void SavePicture(BitmapEncoder encoder, BitmapFrame frame, string path)
        {
            encoder.Frames.Add(frame);
            FileStream file = File.Create(path);
            try
            {
                encoder.Save(file);
            }
            finally
            {
                file.Close();
            }
        }

        // Did OCR find the test picture's words?
        private static bool ReadsTestPicture(string text)
        {
            return text != null && text.IndexOf(TestPictureWord, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        // A long text cut down for the report.
        private static string Shorten(string text)
        {
            string flat = (text ?? "").Replace("\r", " ").Replace("\n", " ");
            return flat.Length > 80 ? flat.Substring(0, 80) + "..." : flat;
        }

        // After a paste: waits (up to 30 seconds) until the message is in the box and checked.
        private async Task<string> WaitForCheckedMessageAsync()
        {
            for (int waited = 0; waited < 30000; waited += 100)
            {
                await Task.Delay(100);
                if (BodyBox.Text.Length > 0 && CheckButton.IsEnabled && ResultView.Visibility == Visibility.Visible)
                {
                    break;
                }
                if (CheckStatus.Text.StartsWith("Couldn't", StringComparison.Ordinal) || CheckStatus.Text.StartsWith("No text", StringComparison.Ordinal))
                {
                    break;   // it failed; the check that follows reports why
                }
            }
            return BodyBox.Text;
        }

        // Runs one named group of checks. If it crashes, that counts as a failure and the next
        // group still runs.
        private async Task Step(string name, Func<Task> body)
        {
            selfTestLog.AppendLine("-- " + name);
            try
            {
                await body();
            }
            catch (Exception ex)
            {
                Expect(name, false, ex.GetType().Name + ": " + ex.Message);
            }
        }

        /*
         * Where would the cursor be in this empty box, and where does the hint's first letter
         * start? Both are asked of WPF itself (GetRectFromCharacterIndex gives the spot of a
         * character, which for character 0 is exactly where the cursor blinks), then compared
         * in the same coordinates. Less than half a pixel apart counts as lined up.
         */
        private void CheckHintAlignment(TextBox box, bool focused)
        {
            string label = (box.Name.Length > 0 ? box.Name : "text box") + (focused ? " (focused)" : "");
            box.ApplyTemplate();
            TextBox hint = box.Template.FindName("Hint", box) as TextBox;
            if (hint == null)
            {
                Expect(label + ": hint found", false, "no Hint in the template");
                return;
            }
            if (box.Text.Length > 0 || hint.Visibility != Visibility.Visible || !box.IsVisible)
            {
                Expect(label + ": hint visible while empty", false, "text '" + box.Text + "', hint " + hint.Visibility);
                return;
            }
            Rect caret = box.GetRectFromCharacterIndex(0);
            Rect hintStart = hint.GetRectFromCharacterIndex(0);
            Point hintInBox = hint.TranslatePoint(new Point(hintStart.X, hintStart.Y), box);
            double dx = Math.Abs(hintInBox.X - caret.X);
            double dy = Math.Abs(hintInBox.Y - caret.Y);
            Expect(label + ": hint lines up with the cursor", dx < 0.5 && dy < 0.5,
                "cursor at " + caret.X.ToString("0.0") + "," + caret.Y.ToString("0.0")
                + "  hint at " + hintInBox.X.ToString("0.0") + "," + hintInBox.Y.ToString("0.0"));
        }
    }
}
