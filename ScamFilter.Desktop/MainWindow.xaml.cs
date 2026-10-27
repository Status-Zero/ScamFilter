using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;

namespace ScamFilter.Desktop
{
    /*
     * Everything the main window does. The layout itself is in MainWindow.xaml; this file
     * reacts to clicks, drops, and pastes, and talks to the backend (ScamFilter.Core):
     *
     *   the form  ->  MessageRecord  ->  ScamDetector.Check()  ->  Verdict  ->  the result panel
     *
     * Every way a message gets in (typing, pasting, a screenshot, an uploaded picture or PDF, an
     * .eml or .msg file, an email dragged from Outlook) ends up as the same MessageRecord,
     * exactly like the training data. The model never knows the difference.
     *
     * "Imported details": a file or rich paste brings things the form has no boxes for (real
     * link targets, sender checks, text read from images). Those ride along in importedRecord
     * until the message is replaced, cleared, or the user picks "Use only the text".
     *
     * Slow work (checking, reading screenshots, training) runs with async/await or Task.Run,
     * so the window never freezes. Code after an "await" continues on the window's thread,
     * which is the only thread allowed to change what's on screen.
     */
    public partial class MainWindow : Window
    {
        // Icons from Windows' built-in icon font
        private static readonly string GlyphSafe = char.ConvertFromUtf32(0xE73E);     // check mark
        private static readonly string GlyphCaution = char.ConvertFromUtf32(0xE7BA);  // warning triangle
        private static readonly string GlyphUnsafe = char.ConvertFromUtf32(0xE711);   // X

        // Everything checked this session, newest first (the History page shows it).
        private readonly ObservableCollection<HistoryItem> history = new ObservableCollection<HistoryItem>();

        // Details from a file, screenshot, or rich paste that the form can't show (see class comment).
        private MessageRecord importedRecord = null;

        // The message and verdict currently shown in the result panel (used by its buttons).
        private MessageRecord lastRecord = null;
        private Verdict lastVerdict = null;

        private bool training = false;

        // Whose ScamFilter this is (see AccountStore), and all accounts on this PC.
        private readonly AccountStore.Store store;
        private readonly Account account;

        public MainWindow(AccountStore.Store store, Account account)
        {
            this.store = store;
            this.account = account;
            Paths.AccountFolder = AccountStore.FolderOf(account);
            ScamDetector.ReloadLists();
            InitializeComponent();
            HistoryList.ItemsSource = history;
            AccountInitial.Text = account.Name.Length > 0 ? account.Name.Substring(0, 1).ToUpperInvariant() : "?";
            AccountNameText.Text = account.Name;
            // The developer tabs only exist in the developer environment (MainWindow.Developer.cs),
            // and so do the Outlook features for now (App.ShowOutlook).
            SetUpDeveloperPages();
            ShowOrHideOutlookFeatures();
            // Watch pastes into the message box (Ctrl+V, Shift+Insert, right-click > Paste), to
            // read screenshots and keep real link targets instead of pasting plain text.
            CommandManager.AddPreviewExecutedHandler(BodyBox, BodyBox_PreviewExecuted);
            // ...and let Paste work there when the clipboard has a picture but no text.
            CommandManager.AddPreviewCanExecuteHandler(BodyBox, BodyBox_PreviewCanExecute);
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            VersionText.Text = "Version " + version.Major + "." + version.Minor;
            FitToScreen();
            Loaded += MainWindow_Loaded;
            Closing += MainWindow_Closing;
            Closed += MainWindow_Closed;
        }

        // On small or zoomed-in screens, shrink the window (and its minimum size) to fit.
        private void FitToScreen()
        {
            Rect area = SystemParameters.WorkArea;
            MinWidth = Math.Min(MinWidth, area.Width);
            MinHeight = Math.Min(MinHeight, area.Height);
            Width = Math.Min(Width, area.Width);
            Height = Math.Min(Height, area.Height);
        }

        // Once the window is on screen: set up the pages, pick up the Outlook sign-in, catch up on
        // anything left from last time (alerts, retraining), and check new mail if that's on.
        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            UpdateHistoryEmpty();
            SetUpProtections();
            Task outlookResume = SetUpOutlookAsync();   // runs while the rest of start-up happens
            if (!ScamDetector.ModelExists())
            {
                // Normally the app comes with a trained model; this only happens if it's missing.
                CheckStatus.Text = "Getting ready. This only takes a few seconds.";
                await TrainAsync();
                CheckStatus.Text = ScamDetector.ModelExists() ? "Ready. Paste a message to check it." : "ScamFilter couldn't get ready. Try restarting it.";
            }
            BodyBox.Focus();
            await outlookResume;
            CheckForOutsideChanges();
            _ = alerts.FlushAsync();   // anything left waiting from last time
            await StartOutlookAutoCheckAsync();
            // Reports saved since the model was last trained: fold them in, quietly, in a bit.
            if (File.Exists(Paths.FeedbackFile) && File.Exists(Paths.ModelFile)
                && File.GetLastWriteTimeUtc(Paths.FeedbackFile) > File.GetLastWriteTimeUtc(Paths.ModelFile))
            {
                ScheduleBackgroundTraining(TimeSpan.FromMinutes(2));
            }
        }

        // The window is closing: lock up (sending the change alert) and stop the timers.
        private void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            LockProtections();   // sends (or saves for next time) the alert about any changes
            if (outlookTimer != null)
            {
                outlookTimer.Stop();
            }
            if (lockTimer != null)
            {
                lockTimer.Stop();
            }
            if (alertRetryTimer != null)
            {
                alertRetryTimer.Stop();
            }
            if (trainingTimer != null)
            {
                trainingTimer.Stop();
            }
        }

        /*
         * The window is gone (the X, Alt+F4, or closing it from the taskbar). If it was the app's
         * main window, close the whole app: every other window and the process itself (see
         * App.OnExit). The one time it isn't: switching accounts, where the next account's window
         * has already taken over as the main window.
         */
        private void MainWindow_Closed(object sender, EventArgs e)
        {
            Application app = Application.Current;
            if (app != null && (app.MainWindow == this || app.MainWindow == null))
            {
                app.Shutdown();
            }
        }

        // =====================================================================
        // Navigation
        // =====================================================================

        private void Nav_Checked(object sender, RoutedEventArgs e)
        {
            // This also fires while the window is still being built, before the pages exist.
            if (PageCheck == null || PageOutlook == null || PageHistory == null || PageLists == null || PageModel == null
                || PageAccount == null || PageAiViewer == null || PageDeveloper == null)
            {
                return;
            }
            PageCheck.Visibility = NavCheck.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            PageOutlook.Visibility = NavOutlook.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            PageHistory.Visibility = NavHistory.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            PageLists.Visibility = NavLists.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            PageAccount.Visibility = NavAccount.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            PageModel.Visibility = NavModel.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            PageAiViewer.Visibility = NavAiViewer.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            PageDeveloper.Visibility = NavDeveloper.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            if (NavOutlook.IsChecked == true)
            {
                OutlookPageShown();
            }
            if (NavLists.IsChecked == true)
            {
                ShowProtections();
            }
            if (NavAccount.IsChecked == true)
            {
                RefreshAccountPage();
            }
            if (NavModel.IsChecked == true)
            {
                RefreshModelInfo();
                LoadLastReport();
            }
            if (NavAiViewer.IsChecked == true)
            {
                RefreshAiViewer();
            }
            if (NavDeveloper.IsChecked == true)
            {
                DeveloperPageShown();
            }
        }

        // Keyboard shortcuts: Ctrl+Enter checks, Ctrl+O uploads a file, Ctrl+V (or Shift+Insert)
        // pastes a message, even a screenshot, and F5 rechecks Outlook.
        private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            bool ctrl = (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control;
            bool shift = (Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift;
            bool pasteKeys = (ctrl && e.Key == Key.V) || (shift && !ctrl && e.Key == Key.Insert);
            if (ctrl && e.Key == Key.Enter && PageCheck.Visibility == Visibility.Visible)
            {
                e.Handled = true;
                _ = CheckCurrentAsync();   // "_ =" means: start it, don't wait here
            }
            else if (e.Key == Key.F5 && PageOutlook.Visibility == Visibility.Visible)
            {
                e.Handled = true;
                _ = RefreshOutlookAsync(false);
            }
            else if (ctrl && e.Key == Key.O)
            {
                e.Handled = true;
                OpenFileButton_Click(sender, null);
            }
            else if (pasteKeys)
            {
                // The message box handles its own text pastes (BodyBox_PreviewExecuted). Other
                // text boxes paste text normally. Anywhere else, Ctrl+V pastes a new message.
                object focused = Keyboard.FocusedElement;
                if (focused == BodyBox)
                {
                    // A screenshot or copied files, with no text: read them right here. (WPF's
                    // text box would ignore the keys, because it only pastes text.)
                    if (!ClipboardHelper.HasMessageText() && (ClipboardHelper.HasImage() || ClipboardHelper.HasFiles()))
                    {
                        e.Handled = true;
                        HandlePaste(true);
                    }
                    return;
                }
                if (focused is TextBox && ClipboardHelper.HasText())
                {
                    return;
                }
                if (focused is TextBox && PageCheck.Visibility != Visibility.Visible)
                {
                    return;   // the list editors and report box keep normal paste behavior
                }
                e.Handled = true;
                NavCheck.IsChecked = true;
                HandlePaste(false);
            }
        }

        // =====================================================================
        // Check page: the form
        // =====================================================================

        private void Type_Checked(object sender, RoutedEventArgs e)
        {
            if (EmailFields == null)
            {
                return;   // still being built
            }
            EmailFields.Visibility = TypeEmail.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            UpdateEmailOnTextHint();
        }

        // The sender box changed: maybe show the "that looks like an email address" hint.
        private void SenderBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            UpdateEmailOnTextHint();
        }

        // A text message whose sender is an email address is unusual; the hint offers to switch to email.
        private void UpdateEmailOnTextHint()
        {
            if (EmailOnTextHint == null || TypeText == null)
            {
                return;   // still being built
            }
            bool show = TypeText.IsChecked == true && SenderBox.Text.IndexOf('@') > 0;
            EmailOnTextHint.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        }

        // "Switch to email" on that hint.
        private void SwitchToEmail_Click(object sender, RoutedEventArgs e)
        {
            TypeEmail.IsChecked = true;
            NameBox.Focus();
        }

        // The message box changed (typed, pasted, or cleared).
        private void BodyBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            // An emptied message box means the imported details no longer belong to anything.
            if (BodyBox.Text.Length == 0 && importedRecord != null && importedRecord.ImageText.Length == 0)
            {
                DetachImport();
            }
        }

        // Turns the form (plus any imported details) into a MessageRecord.
        private MessageRecord BuildRecordFromForm()
        {
            MessageRecord r = importedRecord != null ? importedRecord.Copy() : new MessageRecord();
            r.Type = TypeEmail.IsChecked == true ? "email" : "text";
            r.Sender = SenderBox.Text.Trim();
            r.DisplayName = r.IsEmail() ? NameBox.Text.Trim() : "";
            r.Subject = r.IsEmail() ? SubjectBox.Text : "";
            r.BodyText = BodyBox.Text;
            // A checked box is evidence. An unchecked box means "don't know", never "no".
            r.SenderIsContact = ContactBox.IsChecked == true ? (bool?) true : null;
            r.UserHasReplied = RepliedBox.IsChecked == true ? (bool?) true : null;
            r.Label = -1;
            return r;
        }

        // Puts a record into the form (after importing, or reopening one from History).
        private void FillForm(MessageRecord r)
        {
            if (r.IsEmail())
            {
                TypeEmail.IsChecked = true;
            }
            else
            {
                TypeText.IsChecked = true;
            }
            SenderBox.Text = r.Sender;
            NameBox.Text = r.DisplayName;
            SubjectBox.Text = r.Subject;
            BodyBox.Text = r.BodyText;
            ContactBox.IsChecked = r.SenderIsContact == true;
            RepliedBox.IsChecked = r.UserHasReplied == true;
            importedRecord = r.Copy();   // last, because changing BodyBox can detach the old import
        }

        // Empties the form for a new message.
        private void ClearForm()
        {
            TypeText.IsChecked = true;
            SenderBox.Clear();
            NameBox.Clear();
            SubjectBox.Clear();
            BodyBox.Clear();
            ContactBox.IsChecked = false;
            RepliedBox.IsChecked = false;
            DetachImport();
            CheckStatus.Text = "";
        }

        // Shows the bar that says what was imported (and offers "Use only the text").
        private void ShowImportBar(string text)
        {
            ImportNoteText.Text = text + " ";
            ImportBar.Visibility = Visibility.Visible;
        }

        // Forget the imported details and keep only what's in the form.
        private void DetachImport()
        {
            importedRecord = null;
            ImportBar.Visibility = Visibility.Collapsed;
            SetCheckPageOutlookLink("");
        }

        // "Use only the text" on the import bar.
        private void DetachImport_Click(object sender, RoutedEventArgs e)
        {
            DetachImport();
            CheckStatus.Text = "Now using only the text in the form.";
        }

        // Something brand-new is replacing the message. If the form was filled from an import,
        // all of it (sender, subject, ...) belonged to the old message, so clear it all.
        private void StartNewMessage()
        {
            if (importedRecord != null)
            {
                ClearForm();
            }
        }

        // "Clear": empties the form and hides the result.
        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            ClearForm();
            ResultView.Visibility = Visibility.Collapsed;
            ResultEmpty.Visibility = Visibility.Visible;
            lastRecord = null;
            lastVerdict = null;
            BodyBox.Focus();
        }

        // "Check".
        private async void CheckButton_Click(object sender, RoutedEventArgs e)
        {
            await CheckCurrentAsync();
        }

        // Checks what's in the form (plus any imported details) and shows the result. The check runs
        // off the window's thread, so the window never freezes.
        private async Task CheckCurrentAsync()
        {
            MessageRecord r = BuildRecordFromForm();
            if (r.FullText().Trim().Length == 0)
            {
                CheckStatus.Text = "Paste a message first, or upload a screenshot, photo, PDF, or saved email.";
                BodyBox.Focus();
                return;
            }
            if (!ScamDetector.ModelExists())
            {
                CheckStatus.Text = "ScamFilter is still getting ready. Try again in a moment.";
                return;
            }
            // (Checking keeps working while the model retrains in the background: the new model
            // is swapped in whole when it's done, see ScamModel.Save.)
            CheckButton.IsEnabled = false;
            CheckStatus.Text = "Checking...";
            string outlookKey = pendingOutlookKey;
            pendingOutlookKey = "";
            try
            {
                Verdict v = await Task.Run(() => ScamDetector.Check(r));
                ShowVerdict(r, v);
                AddToHistory(r, v);
                CheckStatus.Text = "";
                if (v.Band == ScamModel.Unsafe)
                {
                    AlertAboutUnsafe(r, v, outlookKey.Length > 0 ? outlookKey : "text:" + ContentKey(r),
                        outlookKey.Length > 0 ? "in their Outlook inbox" : "checked by hand in ScamFilter", DateTime.Now);
                }
            }
            catch (Exception ex)
            {
                CheckStatus.Text = "Couldn't check this message: " + ex.Message;
            }
            finally
            {
                CheckButton.IsEnabled = true;
            }
        }

        // =====================================================================
        // Check page: pasting
        // =====================================================================

        // Pastes into the message box go through here first.
        private void BodyBox_PreviewExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            if (e.Command == ApplicationCommands.Paste && HandlePaste(true))
            {
                e.Handled = true;
            }
        }

        /*
         * Is Paste allowed in the message box right now? A WPF text box only allows Paste when
         * the clipboard has TEXT. A copied screenshot has none, so the text box quietly ignored
         * Ctrl+V and greyed out Paste in its right-click menu: pasting a screenshot did nothing.
         * This says yes to pictures and copied files too, and BodyBox_PreviewExecuted reads them.
         */
        private void BodyBox_PreviewCanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            if (e.Command == ApplicationCommands.Paste && (ClipboardHelper.HasImage() || ClipboardHelper.HasFiles()))
            {
                e.CanExecute = true;
                e.Handled = true;
            }
        }

        /*
         * Decides what a paste means, best clue first:
         *   1. a picture (and no message text)  -> read its text with OCR
         *   2. files copied in Explorer         -> open the first one
         *   3. HTML with links                  -> keep where each link REALLY goes
         *   4. plain text                       -> a normal paste
         * Returns true if it handled the paste, false to let the text box paste normally.
         */
        private bool HandlePaste(bool intoBodyBox)
        {
            if (ClipboardHelper.HasImage() && !ClipboardHelper.HasMessageText())
            {
                PasteScreenshot();
                return true;
            }
            StringCollection files = ClipboardHelper.GetFiles();
            if (files != null && files.Count > 0)
            {
                _ = OpenFileAsync(files[0]);
                return true;
            }

            bool replacingAll = !intoBodyBox || BodyBox.Text.Length == 0 || BodyBox.SelectionLength == BodyBox.Text.Length;
            string html = ClipboardHelper.GetHtml();
            if (html != null)
            {
                List<MessageRecord.UrlRef> links = new List<MessageRecord.UrlRef>();
                string text = EmlImporter.HtmlToText(html, links);
                if (links.Count > 0 && text.Trim().Length > 0)
                {
                    if (replacingAll)
                    {
                        StartNewMessage();
                        BodyBox.Text = text;
                        BodyBox.CaretIndex = text.Length;
                    }
                    else
                    {
                        BodyBox.SelectedText = text;   // replaces the selection (or inserts at the cursor)
                        BodyBox.CaretIndex = BodyBox.SelectionStart + BodyBox.SelectionLength;
                        BodyBox.SelectionLength = 0;
                    }
                    if (importedRecord == null)
                    {
                        importedRecord = new MessageRecord();
                    }
                    importedRecord.Urls.AddRange(links);
                    ShowImportBar("Kept where " + (links.Count == 1 ? "the link" : "all " + links.Count + " links")
                        + " really go, from what you pasted.");
                    BodyBox.Focus();
                    return true;
                }
            }

            if (replacingAll)
            {
                StartNewMessage();   // a new message: forget details from the last import
            }
            if (!intoBodyBox)
            {
                string plain = ClipboardHelper.GetText();
                if (plain == null)
                {
                    return false;
                }
                BodyBox.Text = plain;
                BodyBox.Focus();
                BodyBox.CaretIndex = plain.Length;
                return true;
            }
            return false;   // let the message box paste the text itself
        }

        /*
         * A picture was pasted: read its text with Windows' OCR, then check it. The clipboard can
         * hold the same picture several ways; the best one that works wins (see ClipboardHelper):
         * the PNG copy (exact), then the Bitmap, then the raw DIB pixels, then a picture that
         * copied HTML points to.
         */
        private async void PasteScreenshot()
        {
            NavCheck.IsChecked = true;
            const string Name = "the copied picture";
            try
            {
                byte[] png = ClipboardHelper.GetPng();
                if (png != null)
                {
                    await ImportImageAsync(OcrService.ReadImageBytesAsync(png), Name);
                    return;
                }
                BitmapSource bitmap = ClipboardHelper.GetBitmap();
                if (bitmap != null)
                {
                    await ImportImageAsync(OcrService.ReadBitmapAsync(bitmap, true), Name);
                    return;
                }
                byte[] bmp = ClipboardHelper.GetDibAsBmp();
                if (bmp != null)
                {
                    await ImportImageAsync(OcrService.ReadImageBytesAsync(bmp, true), Name);
                    return;
                }
                byte[] fromHtml = ClipboardHelper.GetHtmlImage();
                if (fromHtml != null)
                {
                    await ImportImageAsync(OcrService.ReadImageBytesAsync(fromHtml), Name);
                    return;
                }
                CheckStatus.Text = "The clipboard says it has a picture, but Windows couldn't hand it over. "
                    + "Copy it again, or save it and use Upload a file.";
            }
            catch (Exception ex)
            {
                CheckStatus.Text = "Couldn't read the copied picture: " + ex.Message;
            }
        }

        // =====================================================================
        // Check page: files and drag-and-drop
        // =====================================================================

        /*
         * Can this be dropped here?
         *   - files from File Explorer, or an email from the new Outlook (it arrives as a file)
         *   - an email or attachment dragged straight out of classic Outlook (a "virtual file")
         *   - a drag from an older new Outlook that can't hand emails over at all: it's still
         *     accepted, so the drop can explain what to do instead of the window just refusing it
         * Dragged text isn't taken here: the text boxes take it themselves.
         */
        private static bool IsDroppable(IDataObject data)
        {
            return data.GetDataPresent(DataFormats.FileDrop) || OutlookDrop.HasVirtualFile(data) || OutlookDrop.IsUnreadableWebDrag(data);
        }

        // Something is being dragged over the window: show the "Drop to check" overlay if it's a
        // file or an Outlook email.
        private void Window_PreviewDragEnter(object sender, DragEventArgs e)
        {
            if (IsDroppable(e.Data))
            {
                DropOverlay.Visibility = Visibility.Visible;
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
            }
        }

        // Keeps the drop allowed while it moves over the window.
        private void Window_PreviewDragOver(object sender, DragEventArgs e)
        {
            if (IsDroppable(e.Data))
            {
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
            }
        }

        // The drag left without dropping: hide the overlay.
        private void DropOverlay_DragLeave(object sender, DragEventArgs e)
        {
            DropOverlay.Visibility = Visibility.Collapsed;
        }

        // Something was dropped: a file, or an email dragged straight out of Outlook.
        private async void Window_PreviewDrop(object sender, DragEventArgs e)
        {
            DropOverlay.Visibility = Visibility.Collapsed;
            if (!IsDroppable(e.Data))
            {
                return;   // dragged text and the like: left to the text boxes
            }
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
            NavCheck.IsChecked = true;
            await HandleDropAsync(e.Data);
        }

        /*
         * Reads what was dropped and checks it. The dragged data only exists during the drop, so
         * EVERYTHING is read before the first "await" (after that, the drop is over):
         *
         *   1. AsyncDrop.Start: the new Outlook only writes the dragged email to a file once it's
         *      told the drop can wait for it (see AsyncDrop.cs). Other sources need nothing.
         *   2. Files: the new Outlook's email file is copied somewhere of our own right away,
         *      because Outlook may delete its copy as soon as the drop is over.
         *   3. A "virtual file" from classic Outlook: its bytes are read (OutlookDrop).
         *   4. AsyncDrop.End: tells the source it's done.
         * Then the file or bytes are opened like any upload.
         */
        internal async Task HandleDropAsync(IDataObject data)
        {
            AsyncDrop transfer = AsyncDrop.Start(data);
            string file = null;         // the dropped file to open (a copy, for the new Outlook)
            string ownCopy = null;      // the folder holding that copy, deleted at the end
            int fileCount = 0;
            byte[] virtualBytes = null; // classic Outlook's email (or attachment) bytes
            string virtualName = "";
            try
            {
                if (data.GetDataPresent(DataFormats.FileDrop))
                {
                    string[] files = data.GetData(DataFormats.FileDrop) as string[];
                    if (files != null && files.Length > 0 && File.Exists(files[0]))
                    {
                        fileCount = files.Length;
                        file = files[0];
                        if (transfer != null)
                        {
                            ownCopy = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "scamfilter_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(ownCopy);
                            string copy = System.IO.Path.Combine(ownCopy, System.IO.Path.GetFileName(file));
                            File.Copy(file, copy);
                            file = copy;
                        }
                    }
                }
                if (file == null && OutlookDrop.HasVirtualFile(data))
                {
                    virtualName = OutlookDrop.FirstFileName(data);
                    virtualBytes = OutlookDrop.ReadFirstFile(data);
                }
            }
            catch (Exception)
            {
                // nothing could be read; explained below
            }
            finally
            {
                if (transfer != null)
                {
                    transfer.End(file != null || (virtualBytes != null && virtualBytes.Length > 0));
                }
            }

            try
            {
                if (file != null)
                {
                    await OpenFileAsync(file);
                    if (fileCount > 1)
                    {
                        CheckStatus.Text = "Checked the first of the " + fileCount + " files you dropped.";
                    }
                }
                else if (virtualBytes != null && virtualBytes.Length > 0)
                {
                    await OpenBytesAsync(virtualBytes, virtualName.Length > 0 ? virtualName : "the dragged email");
                }
                else
                {
                    CheckStatus.Text = OutlookDrop.IsFromWebOutlook(data)
                        ? "This version of Outlook didn't hand the email over. Open the email, choose the ... menu, then "
                          + "Save as (or Download), and upload the saved file with Upload a file."
                        : "Couldn't read that straight from Outlook. Drag it to your desktop first, then drop the saved file here.";
                }
            }
            finally
            {
                if (ownCopy != null)
                {
                    try
                    {
                        Directory.Delete(ownCopy, true);
                    }
                    catch (Exception)
                    {
                        // still in use; it's in the temporary folder anyway
                    }
                }
            }
        }

        /*
         * "Upload a file" (Ctrl+O): Windows' Open window, showing everything ScamFilter reads.
         * The first choice in "Files of type" shows them all; the others narrow it down.
         */
        private void OpenFileButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.Title = "Upload a screenshot, photo, PDF, or email to check";
            string pictures = OcrService.ImageFilePattern;
            dialog.Filter = "Everything ScamFilter can read|" + pictures + ";*.pdf;*.eml;*.msg;*.txt;*.htm;*.html"
                + "|Screenshots and photos|" + pictures
                + "|PDF documents|*.pdf"
                + "|Emails (.eml, .msg)|*.eml;*.msg"
                + "|Text and web pages|*.txt;*.htm;*.html"
                + "|All files|*.*";
            if (dialog.ShowDialog(this) == true)
            {
                NavCheck.IsChecked = true;
                _ = OpenFileAsync(dialog.FileName);
            }
        }

        /*
         * Reads any supported file into the form, then checks it. Usually the extension says what
         * a file is. When it doesn't (no extension, or one ScamFilter doesn't know), the file's
         * first bytes do: every PDF, picture, and .msg starts with its own fixed "signature".
         */
        private async Task OpenFileAsync(string path)
        {
            string name = System.IO.Path.GetFileName(path);
            string ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
            try
            {
                bool known = ext == ".eml" || ext == ".msg" || ext == ".pdf" || ext == ".htm" || ext == ".html" || ext == ".txt"
                    || OcrService.IsImageFile(path);
                if (!known)
                {
                    byte[] start = ReadStart(path, 1024);
                    ext = PdfImporter.LooksLikePdf(start) ? ".pdf"
                        : OcrService.LooksLikeImage(start) ? ".png"
                        : MsgImporter.LooksLikeMsg(start) ? ".msg" : ext;
                }
                if (ext == ".pdf")
                {
                    await ImportPdfAsync(path, name);
                }
                else if (ext == ".eml")
                {
                    CheckStatus.Text = "Reading the email...";
                    EmlImporter.Result result = await Task.Run(() => EmlImporter.Load(path));
                    await ImportEmailAsync(result, name);
                }
                else if (ext == ".msg")
                {
                    CheckStatus.Text = "Reading the Outlook email...";
                    EmlImporter.Result result = await Task.Run(() => MsgImporter.Load(path));
                    await ImportEmailAsync(result, name);
                }
                else if (ext == ".png" || OcrService.IsImageFile(path))
                {
                    await ImportImageAsync(OcrService.ReadImageFileAsync(path), name);
                }
                else if (ext == ".htm" || ext == ".html")
                {
                    MessageRecord r = new MessageRecord();
                    r.Type = "email";
                    r.BodyText = EmlImporter.HtmlToText(File.ReadAllText(path), r.Urls);
                    ClearForm();
                    FillForm(r);
                    ShowImportBar("Using the text and real link targets from " + name + ".");
                    await CheckCurrentAsync();
                }
                else if (ext == ".txt")
                {
                    ClearForm();
                    BodyBox.Text = File.ReadAllText(path);
                    await CheckCurrentAsync();
                }
                else
                {
                    CheckStatus.Text = "ScamFilter reads screenshots and photos (.png, .jpg, and similar), PDFs, emails (.eml, .msg), "
                        + "and .txt or .html files.";
                }
            }
            catch (Exception ex)
            {
                CheckStatus.Text = "Couldn't read " + name + ": " + ex.Message;
            }
        }

        // The first `count` bytes of a file (fewer if it's shorter).
        private static byte[] ReadStart(string path, int count)
        {
            FileStream stream = File.OpenRead(path);
            try
            {
                byte[] buffer = new byte[(int) Math.Min(count, stream.Length)];
                int read = 0;
                while (read < buffer.Length)
                {
                    int n = stream.Read(buffer, read, buffer.Length - read);
                    if (n == 0)
                    {
                        break;
                    }
                    read += n;
                }
                return buffer;
            }
            finally
            {
                stream.Close();
            }
        }

        /*
         * Something dragged straight out of Outlook: usually an email (.msg bytes, or .eml bytes
         * from other programs), but it can be an attachment too, like a PDF invoice or a picture.
         */
        private async Task OpenBytesAsync(byte[] bytes, string name)
        {
            try
            {
                if (PdfImporter.LooksLikePdf(bytes))
                {
                    // Windows' PDF reader works on files, so the PDF gets a temporary one.
                    string temp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "scamfilter_" + Guid.NewGuid().ToString("N") + ".pdf");
                    File.WriteAllBytes(temp, bytes);
                    try
                    {
                        await ImportPdfAsync(temp, name);
                    }
                    finally
                    {
                        File.Delete(temp);
                    }
                    return;
                }
                if (OcrService.LooksLikeImage(bytes))
                {
                    await ImportImageAsync(OcrService.ReadImageBytesAsync(bytes), name);
                    return;
                }
                CheckStatus.Text = "Reading the email...";
                EmlImporter.Result result = await Task.Run(() =>
                {
                    MemoryStream stream = new MemoryStream(bytes);
                    return MsgImporter.LooksLikeMsg(bytes) ? MsgImporter.Load(stream) : EmlImporter.Load(stream);
                });
                await ImportEmailAsync(result, name);
            }
            catch (Exception ex)
            {
                CheckStatus.Text = "Couldn't read " + name + ": " + ex.Message;
            }
        }

        // Puts an imported email in the form (pictures read with OCR first) and checks it.
        private async Task ImportEmailAsync(EmlImporter.Result result, string name)
        {
            MessageRecord r = result.Record;
            // Text hidden inside pictures (a common trick to get past text filters)
            if (result.Images.Count > 0)
            {
                CheckStatus.Text = "Reading the text in the email's pictures...";
                StringBuilder imageText = new StringBuilder();
                foreach (byte[] image in result.Images)
                {
                    try
                    {
                        imageText.AppendLine(await OcrService.ReadImageBytesAsync(image));
                    }
                    catch (Exception)
                    {
                        // A picture that can't be read (or OCR isn't available) just adds nothing.
                    }
                }
                r.ImageText = imageText.ToString().Trim();
            }
            ClearForm();
            FillForm(r);
            bool hasChecks = r.Spf.Length > 0 || r.Dkim.Length > 0 || r.Dmarc.Length > 0;
            ShowImportBar("Using " + (r.Urls.Count > 0 ? "the real link targets" : "the details")
                + (hasChecks ? " and sender checks" : "") + " from " + name + ".");
            await CheckCurrentAsync();
        }

        /*
         * Puts a PDF in the form and checks it. Text pages give their text and real link targets
         * (PdfImporter); scanned pages are read with OCR (OcrService.ReadPdfPagesAsync). If every
         * page was scanned, the whole message is OCR text, marked as such; if only some were, their
         * text rides along as "text in pictures", like the pictures in an email.
         */
        private async Task ImportPdfAsync(string path, string name)
        {
            CheckStatus.Text = "Reading the PDF...";
            PdfImporter.Result result;
            bool readAllWithOcr = false;
            try
            {
                result = await Task.Run(() => PdfImporter.Load(path));
            }
            catch (PdfImporter.PasswordProtectedException ex)
            {
                CheckStatus.Text = ex.Message;
                return;
            }
            catch (Exception)
            {
                // A PDF too damaged for PdfPig: Windows' own PDF reader may still draw its pages.
                result = new PdfImporter.Result();
                result.Record.Type = "email";
                readAllWithOcr = true;
            }
            MessageRecord r = result.Record;
            if (readAllWithOcr || result.ScannedPages.Count > 0)
            {
                string ocrText;
                try
                {
                    ocrText = await OcrService.ReadPdfPagesAsync(path, readAllWithOcr ? null : result.ScannedPages,
                        status => CheckStatus.Text = status);
                }
                catch (Exception ex)
                {
                    CheckStatus.Text = "Couldn't read " + name + ": " + ex.Message;
                    return;
                }
                if (r.BodyText.Trim().Length == 0)
                {
                    r.BodyText = ocrText;
                    r.Channel = "ocr";   // all of it was read from pictures (see OcrService)
                }
                else
                {
                    r.ImageText = ocrText;
                }
            }
            if (r.FullText().Trim().Length == 0)
            {
                CheckStatus.Text = "No text was found in " + name + ".";
                return;
            }
            ClearForm();
            FillForm(r);
            string note = "Using the text" + (r.Urls.Count > 0 ? " and the real link targets" : "") + " from " + name;
            if (result.Truncated)
            {
                note += " (its first " + PdfImporter.MaxPages + " pages)";
            }
            note += ".";
            if (r.IsOcr())
            {
                note += " It's a scanned PDF, so its text was read from pictures, which can make small mistakes: letter swaps "
                    + "in links (like paypa1 for paypal) aren't judged.";
            }
            else if (r.ImageText.Length > 0)
            {
                note += " Its scanned pages were read from pictures too.";
            }
            ShowImportBar(note);
            await CheckCurrentAsync();
        }

        // Puts text read out of a picture into the form as an OCR message, then checks it.
        private async Task ImportImageAsync(Task<string> reading, string name)
        {
            CheckStatus.Text = "Reading the text in " + name + "...";
            string text;
            try
            {
                text = await reading;
            }
            catch (Exception ex)
            {
                CheckStatus.Text = "Couldn't read the text in " + name + ": " + ex.Message;
                return;
            }
            if (text.Length == 0)
            {
                CheckStatus.Text = "No text was found in " + name + ".";
                return;
            }
            string typedSender = importedRecord == null ? SenderBox.Text.Trim() : "";   // keep a sender the user typed
            string foundSender = typedSender.Length == 0 ? OcrService.GuessSender(text) : "";
            MessageRecord r = new MessageRecord();
            r.Type = "text";
            r.Sender = typedSender.Length > 0 ? typedSender : foundSender;
            r.BodyText = text;
            r.Channel = "ocr";
            ClearForm();
            FillForm(r);
            ShowImportBar("Text read from " + name + "."
                + (foundSender.Length > 0 ? " The sender looks like " + foundSender + "; fix it above if that's wrong." : "")
                + " Reading text from pictures can make small mistakes, so letter swaps in links (like paypa1 for paypal) aren't judged.");
            await CheckCurrentAsync();
        }

        // =====================================================================
        // Check page: the result panel
        // =====================================================================

        private void ShowVerdict(MessageRecord r, Verdict v)
        {
            lastRecord = r;
            lastVerdict = v;
            ResultEmpty.Visibility = Visibility.Collapsed;
            ResultView.Visibility = Visibility.Visible;
            ResultView.ScrollToTop();

            Brush brush = BandBrush(v.Band);
            VerdictBand.Background = brush;
            if (v.Band == ScamModel.Unsafe)
            {
                VerdictIcon.Text = GlyphUnsafe;
                VerdictTitle.Text = "Unsafe";
                VerdictSummary.Text = "This looks like a scam. Don't click its links, reply to it, or call any number in it.";
            }
            else if (v.Band == ScamModel.Caution)
            {
                VerdictIcon.Text = GlyphCaution;
                VerdictTitle.Text = "Caution";
                VerdictSummary.Text = "Something about this is off. Before you act on it, contact the sender another way: "
                    + "their official app or website, or a number you already know.";
            }
            else
            {
                VerdictIcon.Text = GlyphSafe;
                VerdictTitle.Text = "Looks safe";
                VerdictSummary.Text = "No warning signs found. Still be careful with links and requests you weren't expecting.";
            }
            if (v.DecidedBy == "blocklist")
            {
                VerdictSummary.Text = "The sender, or a site this message links to, is on your blocked list.";
            }
            else if (v.DecidedBy == "whitelist" && v.Band == ScamModel.Safe)
            {
                VerdictSummary.Text = "You trust this sender, and nothing in the message is on your blocked list.";
            }
            else if (v.DecidedBy == "whitelist")
            {
                VerdictSummary.Text = "This came from a sender you trust, but it reads like a scam. Their account may have "
                    + "been hacked: check with them another way before you do anything it asks.";
            }

            // Why
            ReasonsList.Children.Clear();
            foreach (string line in FriendlyReasons(v))
            {
                ReasonsList.Children.Add(MakeBullet(line, brush));
            }

            // Links, as plain text that can't be clicked
            LinksList.Children.Clear();
            int shown = 0;
            foreach (LinkInfo link in v.Links)
            {
                if (shown >= 8)
                {
                    break;
                }
                LinksList.Children.Add(MakeLinkView(link, brush));
                shown++;
            }
            if (v.Links.Count > shown)
            {
                TextBlock more = new TextBlock();
                more.Style = (Style) FindResource("Caption");
                more.Text = "And " + (v.Links.Count - shown) + " more.";
                LinksList.Children.Add(more);
            }
            LinksSection.Visibility = v.Links.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

            // Buttons that make sense for this result
            bool hasSender = r.Sender.Trim().Length > 0;
            BlockSenderButton.Visibility = hasSender && v.DecidedBy != "blocklist" ? Visibility.Visible : Visibility.Collapsed;
            TrustSenderButton.Visibility = hasSender && v.DecidedBy != "whitelist" ? Visibility.Visible : Visibility.Collapsed;
            BlockSitesButton.Visibility = v.Band != ScamModel.Safe && SitesToBlock(v).Count > 0
                ? Visibility.Visible : Visibility.Collapsed;
            MarkScamButton.Visibility = v.Band != ScamModel.Unsafe ? Visibility.Visible : Visibility.Collapsed;
            MarkSafeButton.Visibility = v.Band != ScamModel.Safe ? Visibility.Visible : Visibility.Collapsed;
            CorrectionArea.Visibility = Visibility.Visible;
            CorrectionSaved.Visibility = Visibility.Collapsed;

            if (App.DeveloperMode)
            {
                DetailsBox.Text = ScoringBreakdown(r, v);   // shown on the AI viewer
            }
        }

        /*
         * The reasons in plain words. Metadata flags already read like sentences
         * ("A domain imitates a well-known brand"). Text features get grouped into one line of
         * example wording; pieces of words and number patterns are left out because they mean
         * nothing to a person.
         */
        private static List<string> FriendlyReasons(Verdict v)
        {
            List<string> lines = new List<string>();
            List<string> wording = new List<string>();
            foreach (Reason reason in v.Reasons)
            {
                if (reason.IsFlag)
                {
                    lines.Add(reason.Label);
                }
                else if (reason.Label.StartsWith("word ", StringComparison.Ordinal)
                         || reason.Label.StartsWith("phrase ", StringComparison.Ordinal))
                {
                    string quoted = reason.Label.Substring(reason.Label.IndexOf('"'));
                    string inner = quoted.Trim('"').Replace("[link]", "").Replace("[email]", "");
                    if (HasLetter(inner) && !wording.Contains(quoted))
                    {
                        wording.Add(quoted);
                    }
                }
            }
            if (wording.Count > 0)
            {
                lines.Add((v.Band == ScamModel.Safe
                    ? "Wording that's typical of normal messages: "
                    : "Wording that often shows up in scams: ") + string.Join(", ", wording));
            }
            if (lines.Count == 0)
            {
                lines.Add(v.Band == ScamModel.Safe
                    ? "Nothing in it matched the warning signs the model looks for."
                    : "Its overall wording resembles scams the model learned from.");
            }
            return lines;
        }

        // Does the text contain at least one letter?
        private static bool HasLetter(string s)
        {
            foreach (char c in s)
            {
                if (char.IsLetter(c))
                {
                    return true;
                }
            }
            return false;
        }

        // One bullet point for the "Why" list, in the verdict's color.
        private UIElement MakeBullet(string text, Brush color)
        {
            Grid row = new Grid();
            row.Margin = new Thickness(0, 0, 0, 8);
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(18) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Ellipse dot = new Ellipse();
            dot.Width = 7;
            dot.Height = 7;
            dot.Fill = color;
            dot.VerticalAlignment = VerticalAlignment.Top;
            dot.Margin = new Thickness(0, 7, 0, 0);
            TextBlock label = new TextBlock();
            label.Text = text;
            label.TextWrapping = TextWrapping.Wrap;
            label.LineHeight = 20;
            Grid.SetColumn(label, 1);
            row.Children.Add(dot);
            row.Children.Add(label);
            return row;
        }

        /*
         * One link:
         *   paypa1-secure.com/resolve?id=88f2a                       (where it really goes)
         *   ! The message shows www.paypal.com/resolve, but ...      (each warning)
         *   Unwrapped from a link-protection service                 (neutral note)
         */
        private UIElement MakeLinkView(LinkInfo link, Brush warningColor)
        {
            StackPanel panel = new StackPanel();
            panel.Margin = new Thickness(0, 0, 0, 12);

            TextBlock target = new TextBlock();
            target.Text = link.Target;
            target.FontFamily = (FontFamily) FindResource("CodeFont");
            target.FontSize = 13;
            target.TextWrapping = TextWrapping.Wrap;
            panel.Children.Add(target);

            foreach (string warning in link.Warnings)
            {
                Grid row = new Grid();
                row.Margin = new Thickness(0, 4, 0, 0);
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(20) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                TextBlock icon = new TextBlock();
                icon.Text = GlyphCaution;
                icon.FontFamily = (FontFamily) FindResource("IconFont");
                icon.FontSize = 12;
                icon.Foreground = warningColor == (Brush) FindResource("SafeBrush") ? (Brush) FindResource("CautionBrush") : warningColor;
                icon.Margin = new Thickness(0, 3, 0, 0);
                TextBlock text = new TextBlock();
                text.Text = warning;
                text.FontSize = 13;
                text.TextWrapping = TextWrapping.Wrap;
                Grid.SetColumn(text, 1);
                row.Children.Add(icon);
                row.Children.Add(text);
                panel.Children.Add(row);
            }
            if (link.Note.Length > 0)
            {
                TextBlock note = new TextBlock();
                note.Style = (Style) FindResource("Caption");
                note.Text = link.Note;
                note.Margin = new Thickness(0, 4, 0, 0);
                panel.Children.Add(note);
            }
            return panel;
        }

        // The numbers behind the verdict, for anyone curious (and for debugging the model).

        private static string Dash(string s)
        {
            return s.Length > 0 ? s : "-";
        }

        // The color for a band (green, amber, red).
        private Brush BandBrush(string band)
        {
            if (band == ScamModel.Unsafe)
            {
                return (Brush) FindResource("UnsafeBrush");
            }
            if (band == ScamModel.Caution)
            {
                return (Brush) FindResource("CautionBrush");
            }
            return (Brush) FindResource("SafeBrush");
        }

        // "Safe", "Caution" or "Unsafe".
        private static string BandName(string band)
        {
            if (band == ScamModel.Unsafe)
            {
                return "Unsafe";
            }
            if (band == ScamModel.Caution)
            {
                return "Caution";
            }
            return "Safe";
        }

        // The sites a message links to that could sensibly go on the blocked list.
        private static List<string> SitesToBlock(Verdict v)
        {
            List<string> sites = new List<string>();
            foreach (LinkInfo link in v.Links)
            {
                string host = UrlAnalyzer.Host(link.Target);
                if (host.Length == 0 || UrlAnalyzer.IsIp(host) || UrlAnalyzer.IsShortener(host)
                    || UrlAnalyzer.IsFreeMail(host) || UrlAnalyzer.IsClickTracker(host))
                {
                    continue;   // blocking these would block far more than this one scam
                }
                string site = UrlAnalyzer.RegisteredDomain(host);
                if (!sites.Contains(site))
                {
                    sites.Add(site);
                }
            }
            return sites;
        }

        // ---- Result buttons ----

        private async void BlockSenderButton_Click(object sender, RoutedEventArgs e)
        {
            if (lastRecord == null)
            {
                return;
            }
            string sender1 = MetadataFeatures.EmailAddress(lastRecord.Sender);
            CheckStatus.Text = AddToBlocked(sender1.Length > 0 ? sender1 : lastRecord.Sender.Trim(), "");
            await RecheckLastAsync();
        }

        // "Block these sites": blocks the suspicious sites the message links to.
        private async void BlockSitesButton_Click(object sender, RoutedEventArgs e)
        {
            if (lastVerdict == null)
            {
                return;
            }
            List<string> sites = SitesToBlock(lastVerdict);
            MessageBoxResult answer = MessageBox.Show(this,
                "Mark every message that links to these sites as unsafe?\n\n" + string.Join("\n", sites),
                "Block these sites", MessageBoxButton.OKCancel, MessageBoxImage.Question);
            if (answer != MessageBoxResult.OK)
            {
                return;
            }
            List<string> results = new List<string>();
            foreach (string site in sites)
            {
                results.Add(AddToBlocked(site, ""));
            }
            CheckStatus.Text = string.Join(" ", results);
            await RecheckLastAsync();
        }

        // "Trust sender": checked against the rules, then needs the password.
        private async void TrustSenderButton_Click(object sender, RoutedEventArgs e)
        {
            if (lastRecord == null || lastVerdict == null)
            {
                return;
            }
            if (lastVerdict.Band == ScamModel.Unsafe)
            {
                MessageBoxResult answer = MessageBox.Show(this,
                    "This message looks like a scam. Trust " + lastRecord.Sender + " anyway?\n\n"
                    + "Messages from trusted senders are marked safe unless they look like a scam.",
                    "Trust sender", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes)
                {
                    return;
                }
            }
            string address = MetadataFeatures.EmailAddress(lastRecord.Sender);
            CheckStatus.Text = await AddToTrustedAsync(address.Length > 0 ? address : lastRecord.Sender.Trim(), lastRecord.DisplayName.Trim());
            await RecheckLastAsync();
        }

        // "This is a scam": saves the message as a correction for the next training run.
        private void MarkScamButton_Click(object sender, RoutedEventArgs e)
        {
            SaveCorrection(1);
        }

        // "This is safe": the same, the other way.
        private void MarkSafeButton_Click(object sender, RoutedEventArgs e)
        {
            SaveCorrection(0);
        }

        /*
         * Saves the right answer as a new training example (data\feedback.jsonl). These are the
         * most useful training data there is: real messages, with real details, labeled by the
         * person who received them.
         */
        private void SaveCorrection(int label)
        {
            if (lastRecord == null)
            {
                return;
            }
            try
            {
                ScamDetector.SaveCorrection(lastRecord, label);
            }
            catch (Exception ex)
            {
                CheckStatus.Text = "Couldn't save that: " + ex.Message;
                return;
            }
            CorrectionArea.Visibility = Visibility.Collapsed;
            CorrectionSavedText.Text = "Thanks. ScamFilter will learn from this in the background in a minute or two.";
            CorrectionSaved.Visibility = Visibility.Visible;
            ScheduleBackgroundTraining(TimeSpan.FromMinutes(1));
        }

        // =====================================================================
        // Learning from reports, in the background
        // =====================================================================

        /*
         * Reports ("This is a scam" / "This is safe") are folded into the model without anyone
         * pressing a button: a minute after the last report (so several reports in a row become
         * one training run), the model retrains on a background thread. Checking keeps working
         * the whole time with the old model, and the new one is swapped in when it's done.
         * Other open ScamFilter windows pick the new model up by themselves (ScamDetector notices
         * the file changed).
         */
        private DispatcherTimer trainingTimer = null;

        // Retrains in the background after `delay` (starting the wait over if it's already waiting).
        private void ScheduleBackgroundTraining(TimeSpan delay)
        {
            if (trainingTimer == null)
            {
                trainingTimer = new DispatcherTimer();
                trainingTimer.Tick += async (s, args) =>
                {
                    trainingTimer.Stop();
                    if (Trainer.IsTrainingElsewhere())
                    {
                        // Another ScamFilter window is training. Try again once it's had time to
                        // finish, so this window's newest reports are in the next model too.
                        ScheduleBackgroundTraining(TimeSpan.FromMinutes(2));
                        return;
                    }
                    await TrainAsync();
                };
            }
            trainingTimer.Stop();   // starting over: wait the full delay after the latest report
            trainingTimer.Interval = delay;
            trainingTimer.Start();
        }

        // After a change (lists, retraining), the same message can get a different verdict.
        private async Task RecheckLastAsync()
        {
            if (lastRecord == null || !ScamDetector.ModelExists())
            {
                return;
            }
            MessageRecord r = lastRecord;
            try
            {
                Verdict v = await Task.Run(() => ScamDetector.Check(r));
                ShowVerdict(r, v);
            }
            catch (Exception ex)
            {
                CheckStatus.Text = "Couldn't check this message again: " + ex.Message;
            }
        }

        // =====================================================================
        // History page
        // =====================================================================

        private void AddToHistory(MessageRecord r, Verdict v)
        {
            HistoryItem item = new HistoryItem();
            item.Time = DateTime.Now.ToString("h:mm tt");
            item.BandText = BandName(v.Band);
            item.BandBrush = BandBrush(v.Band);
            item.Preview = r.Preview(140);
            item.Record = r;
            item.Verdict = v;
            history.Insert(0, item);   // newest first
            UpdateHistoryEmpty();
        }

        // Shows "Nothing checked yet" or the list.
        private void UpdateHistoryEmpty()
        {
            HistoryEmpty.Visibility = history.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            HistoryList.Visibility = history.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
            ClearHistoryButton.Visibility = history.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        }

        // Clicking a History row shows that result again on the Check page.
        private void HistoryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            HistoryItem item = HistoryList.SelectedItem as HistoryItem;
            if (item == null)
            {
                return;
            }
            ClearForm();
            FillForm(item.Record);
            if (item.Record.Urls.Count > 0 || item.Record.Dmarc.Length > 0 || item.Record.IsOcr() || item.Record.ImageText.Length > 0)
            {
                ShowImportBar("Reopened from History, with the details it was checked with.");
            }
            ShowVerdict(item.Record, item.Verdict);
            HistoryList.SelectedItem = null;   // so selecting the same row again works too
            NavCheck.IsChecked = true;
        }

        // "Clear history".
        private void ClearHistoryButton_Click(object sender, RoutedEventArgs e)
        {
            history.Clear();
            UpdateHistoryEmpty();
        }

        // =====================================================================
        // Model page (developer environment only, see App.xaml.cs)
        // =====================================================================

        private void RefreshModelInfo()
        {
            int records = CountRecords(Paths.RecordsFile);
            int corrections = CountRecords(Paths.FeedbackFile);
            ModelData.Text = records.ToString("N0") + " in records.jsonl, plus " + corrections.ToString("N0")
                + (corrections == 1 ? " result" : " results") + " you've marked";
            if (!ScamDetector.ModelExists())
            {
                ModelTrained.Text = "Not trained yet";
                ModelFeatures.Text = "-";
                ModelThresholds.Text = "-";
                return;
            }
            ModelTrained.Text = LastTrained().ToString("MMMM d, yyyy 'at' h:mm tt");
            try
            {
                ScamModel model = ScamDetector.CurrentModel();
                ModelFeatures.Text = model.Featurizer.Size.ToString("N0") + " words and word pieces";
                ModelThresholds.Text = "Safe below a " + Format.Percent(model.TLow, 0) + "% scam probability, unsafe from "
                    + Format.Percent(model.THigh, 0) + "%, caution in between";
            }
            catch (Exception ex)
            {
                ModelFeatures.Text = "Couldn't read the model: " + ex.Message;
                ModelThresholds.Text = "-";
            }
        }

        // When the model was trained: the first line of its report says ("Trained 2026-10-24 11:09").
        // The built-in model is copied in at install time, so the file's own date would be wrong.
        private static DateTime LastTrained()
        {
            try
            {
                if (File.Exists(Paths.ReportFile))
                {
                    string first = File.ReadLines(Paths.ReportFile).FirstOrDefault() ?? "";
                    DateTime when;
                    if (first.StartsWith("Trained ", StringComparison.Ordinal)
                        && DateTime.TryParseExact(first.Substring(8).Trim(), "yyyy-MM-dd HH:mm",
                               System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out when))
                    {
                        return when;
                    }
                }
            }
            catch (IOException)
            {
                // fall back to the model file's date
            }
            return File.GetLastWriteTime(Paths.ModelFile);
        }

        // Shows the report from the last training run, if this session hasn't trained yet.
        private void LoadLastReport()
        {
            if (TrainLog.Text.Length > 0 || training || !File.Exists(Paths.ReportFile))
            {
                return;
            }
            try
            {
                TrainLog.Text = File.ReadAllText(Paths.ReportFile).Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
            }
            catch (Exception)
            {
                // no report to show is fine
            }
        }

        // How many records a .jsonl file has (blank lines don't count).
        private static int CountRecords(string path)
        {
            if (!File.Exists(path))
            {
                return 0;
            }
            int count = 0;
            foreach (string line in File.ReadAllLines(path))
            {
                if (line.Trim().Length > 0)
                {
                    count++;
                }
            }
            return count;
        }

        // "Train model" on the Model page.
        private async void TrainButton_Click(object sender, RoutedEventArgs e)
        {
            await TrainAsync();
        }

        // Trains the model on a background thread and shows the report as it's written.
        private async Task TrainAsync()
        {
            if (training)
            {
                return;
            }
            training = true;
            TrainButton.IsEnabled = false;
            TrainProgress.Visibility = Visibility.Visible;
            TrainLog.Clear();
            try
            {
                // Training runs on a background thread. Each report line is handed back to the
                // window's thread (Dispatcher.BeginInvoke), the only one allowed to update the screen.
                await Task.Run(() => Trainer.Train(new TrainingSettings(), line =>
                    Dispatcher.BeginInvoke(new Action(() => TrainLog.AppendText(line + Environment.NewLine)))));
            }
            catch (Exception ex)
            {
                TrainLog.AppendText(Environment.NewLine + "Training failed: " + ex.Message + Environment.NewLine);
            }
            finally
            {
                training = false;
                TrainButton.IsEnabled = true;
                TrainProgress.Visibility = Visibility.Hidden;
                RefreshModelInfo();
                // Lower priority, so it runs after the last report lines have been added.
                _ = Dispatcher.BeginInvoke(new Action(() => TrainLog.ScrollToEnd()), System.Windows.Threading.DispatcherPriority.Background);
            }
        }

        // "Open data folder": opens it in File Explorer.
        private void OpenDataFolderButton_Click(object sender, RoutedEventArgs e)
        {
            Directory.CreateDirectory(Paths.DataFolder);
            ProcessStartInfo info = new ProcessStartInfo();
            info.FileName = Paths.DataFolder;
            info.UseShellExecute = true;   // lets Windows open the folder in File Explorer
            Process.Start(info);
        }
    }
}
