# ScamFilter

A Windows desktop app that checks texts and emails for scams. Paste a message or a screenshot, or upload a photo, a PDF, or an email file, and it tells you **Safe**, **Caution**, or **Unsafe**, with the reasons why.

Everything runs on your PC. Messages are never uploaded, and links are never opened.

The AI is written from scratch with no AI libraries: the model, training, text features, and metrics are all written from scratch in C#. Libraries handle only the plumbing:

- **MimeKit** reads `.eml` email files, and **MsgReader** reads Outlook `.msg` files.
- **PdfPig** reads the text and links out of PDFs.
- **System.Text.Json** reads the data files.
- **Windows' built-in OCR** reads screenshots, photos and scanned PDF pages, and **Windows' PDF reader** draws those pages.
- **MSAL** (Microsoft's sign-in library) links an Outlook account (developer environment only, for now).
- Passwords are stored as PBKDF2 hashes (built into .NET), never as the password itself.

## Running the app

1. Double-click `ScamFilter.exe`. It's one self-contained file, so nothing needs installing, not even .NET.
2. Windows may show **"Windows protected your PC"**, because the app isn't code-signed (signing certificates cost money every year). Choose **More info → Run anyway**.
3. The first time, make an account: a name and a password. Save the recovery code it shows you.
4. It comes with a model already trained, so it's ready right away.

Its data lives in `%LOCALAPPDATA%\ScamFilter`: shared data and the model, plus one folder per account under `accounts`.

## Using it

**Check a message** has several ways in:
- **Paste an email copied from Outlook or Gmail.** Pasting keeps where each link *really* goes, which is the best clue there is.
- **Paste a screenshot:** take it with Win+Shift+S (or Print Screen, or copy a picture from a web page or app), then press **Ctrl+V**. If the screenshot shows the sender's number at the top, ScamFilter fills it in.
- **Upload a file** (the button, or **Ctrl+O**), or drop one anywhere on the window:
  - **Screenshots and photos:** PNG, JPG, GIF, BMP, TIFF (every page), ICO, JPEG XR, and WebP, HEIC (iPhone photos) and AVIF when Windows has their free Microsoft Store extensions. Phone photos taken sideways are turned upright first.
  - **PDFs**, like an invoice or a statement: text pages are read exactly, with every link's real target; scanned pages are read with OCR. The first 20 pages count; password-protected PDFs can't be read.
  - **Emails:** `.eml` or `.msg` files, and `.txt` / `.html` files.
  - A file with a wrong extension, or none, is recognized by its contents.
- **Drag an email straight out of Outlook** (classic or new) onto the window, or one of its attachments (a PDF or a picture). The new Outlook hands an email over only to programs that say they can wait for it; ScamFilter does (`AsyncDrop.cs`). Some older versions of the new Outlook can't hand emails over at all; ScamFilter then says to save the email and upload it.
- **Type or paste plain text,** then press **Ctrl+Enter** to check.

Text in pictures and scanned pages is read by Windows' own OCR, on this PC. OCR can mix up look-alike letters, so for that text, letter swaps in links (like `paypa1` for `paypal`) aren't held against a message.

Getting an email out as a file:
- **Classic Outlook:** drag it to the desktop to get a `.msg`, or drag it straight into ScamFilter.
- **New Outlook:** drag it straight into ScamFilter, or to the desktop to get an `.eml`.
- **New Outlook / Outlook on the web:** open the email, choose the ... menu, then *Save as* or *Download*.
- **Gmail:** open the email, choose the menu, then *Download message*.

**The result panel:**
- **Why** lists the evidence in plain words.
- **Links in this message** shows where every link really goes. Microsoft 365 *Safe Links* and similar wrappers are unwrapped, and each link's red flags are listed. Links are never opened.
- **Block sender**, **Block these sites**, and **Trust sender** edit your lists. A trusted sender whose message looks like a scam gets *Caution* instead of *Safe*, in case their account was hacked.
- **This is a scam** / **This is safe** report a wrong answer (see *Reports* below).

**Protections** (needs the password for anything that weakens protection):
- **Blocked:** phone numbers, email addresses, or websites whose messages are marked Unsafe right away.
- **Trusted:** senders whose messages are marked Safe, unless they read like a scam (a hacked account).
- Entries are checked against fixed rules (`ListRules.cs`), each refusal explained in plain words. For example: no blocking `gmail.com` (it would block everyone), no blocking or trusting a real company's site (scammers send fake invoices through real companies' systems), no trusting look-alikes like `paypa1.com`, nothing on both lists.
- Unlocking lasts 5 minutes, then locks again.

**Account:** each person on the PC has their own account, with their own lists. Checking messages never needs a password; changing protections does. The recovery code resets a forgotten password. 5 wrong passwords in a row lock it for 5 minutes (doubling after that).
- What it protects against: changes made through ScamFilter, including someone being talked through it on the phone. Someone signed in to the same Windows account could still edit the files directly; ScamFilter fingerprints its protection files and reports changes it didn't make.

**Several windows:** ScamFilter can be open more than once at the same time, for different accounts or the same one. The windows share the data folder safely: saves are merged instead of overwriting each other, wrong passwords count across windows, only one window trains the model at a time (the others pick up the new model by themselves), and each alert goes out once. See `SharedFiles.cs` and the comment at the top of `AccountStore`.

**Other pages:**
- **History:** everything you've checked this session (each window has its own).

**Reports:** *This is a scam* / *This is safe* on a result saves it to `data\feedback.jsonl`. A minute later the model retrains in the background, counting each report five times. There's no training screen for users.

**Developer environment** (for whoever builds ScamFilter): press **Ctrl+Shift+D** while the account window is open (the welcome window, *Switch account*, or *Add an account*), or start `ScamFilter.exe --developer`. It opens without an account and looks exactly like the normal app, plus four developer tabs:
- **Outlook:** linking an Outlook account and checking its mail (below). Developer-only for now.
- **AI viewer:** what the model learned (look up any word's weight; the strongest scam and safe words) and the full arithmetic behind the last message checked: bias + each word's weight x value + each flag = z, then the probability and the band.
- **Model:** train now, and the training report.
- **Developer:** the environment's data folder, *Leave* and *Reset*, and the Outlook app-registration setup.

**Outlook and alerts (developer environment only, for now).** Everything that needs a linked Microsoft account is hidden from normal users and shows only in the developer environment: the Outlook tab, *Use my Microsoft account* when making an account, the Microsoft row on the Account page, and the alerts on the Protections page (alerts are emailed through the linked Outlook). Outside the developer environment, ScamFilter never signs in to Microsoft. To give it all back to everyone, make `App.ShowOutlook` (in `App.xaml.cs`) return `true`.
- **Outlook** checks the newest emails in a linked Outlook account (Outlook.com, Hotmail, Live, or a Microsoft 365 work or school mailbox): a badge on every email, Inbox or Junk Email, newest 25, 50, or 100. Select one for a full check, pictures included; the result opens on the Check page. *Check for new mail every 5 minutes* while the app is open; the red number next to *Outlook* counts unsafe emails. It reads mail but never changes, deletes, or moves it. The sign-in is saved in the account's folder, encrypted by Windows so only your Windows account can read it. *Unlink* deletes it.
- **Alerts** email up to 3 trusted people when a message comes out Unsafe, when the wrong password is entered 5 times, or when protections change (something trusted or unblocked, alerts turned off, Outlook unlinked, the password changed). Sent from the linked Outlook account, with no links in them. Removing a contact or turning an alert off sends one last alert first, and changes made while unlocked go out as one alert.
- A linked Microsoft account can also be used instead of a password to open a ScamFilter account.

It runs in its own folder, `%LOCALAPPDATA%\ScamFilter\Developer`, with its own model, lists, alerts and Outlook sign-in, and needs no password because there's nothing in it to protect: someone talked into opening it gets an empty sandbox, and nothing done there changes a real account or the model real accounts use. *Switch account* inside it leaves it.

**Outlook app registration (for whoever builds ScamFilter):** Microsoft only lets registered apps read mail, so register ScamFilter once (free, about five minutes), then put the ID in `OutlookAppConfig.BuiltInClientId` (in `OutlookAccount.cs`) and rebuild. Everyone using that build just clicks *Sign in with Microsoft*.
  1. In the [Microsoft Entra admin center](https://entra.microsoft.com), open **App registrations → New registration**. If your account has no directory, make a free Azure account first; it comes with one.
  2. Name it ScamFilter. For **Supported account types** pick *Any Entra ID tenant + Personal Microsoft accounts*.
  3. For **Redirect URI** pick *Public client/native (mobile & desktop)* and enter `http://localhost`.
  4. Copy the **Application (client) ID** from the Overview page.
  To try an ID without rebuilding: open the developer environment and paste it on the Developer page. (It's saved for the developer environment only.)

## The code

| Project | What it is |
|---|---|
| `ScamFilter.Core` | The backend: model, training, features, detector. Plain .NET, runs anywhere. |
| `ScamFilter.Desktop` | The WPF app that builds `ScamFilter.exe`. |
| `ScamFilter.Trainer` | Command-line trainer, demo, and dataset importer. |

### Building it

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download). Then any of these:

- **Visual Studio** (Community is free) with the *.NET desktop development* workload: open `ScamFilter.slnx` and press F5 with *ScamFilter.Desktop* as the startup project.
- **Make the .exe:** double-click `build-exe.cmd`. The result goes in `publish\ScamFilter.exe`.
- **Command-line trainer:** from this folder, run
  - `dotnet run --project ScamFilter.Trainer` to train and print the report. It saves `model\scam_model.txt`, which the next build of the app carries as its built-in model.
  - add ` -- demo` at the end to run six demo messages
  - add ` -- help` for the dataset import commands
- **Check the window:** `ScamFilter.exe --self-test` makes a throwaway account in a temporary folder, opens the app off-screen, visits every page and dialog, pastes a test screenshot and uploads test pictures and a PDF (with Windows' real OCR), and writes the results to `%TEMP%\ScamFilterSelfTest\result.txt`. It takes about half a minute.

### New to AI? Read the code in this order

Every class in `ScamFilter.Core` starts with a long comment explaining the ideas it uses, in plain language with worked numbers. You only need to know C# or Java.

1. **`Trainer.cs`**: what "training a model" means, and why data is split into train, validation, and test sets.
2. **`ScamModel.cs`**: how a guess is made (weighted evidence, then the sigmoid, then a probability), and how to read a weight.
3. **`LogisticTrainer.cs`**: how the model learns (loss, gradient descent, overfitting, regularization, early stopping).
4. **`Featurizer.cs`** and **`TextNormalizer.cs`**: how text becomes numbers (bag of words, n-grams, TF-IDF).
5. **`MetadataFeatures.cs`** and **`UrlAnalyzer.cs`**: the hand-built evidence flags and link checks.
   **`EmlImporter.cs`** and **`GraphMail.cs`**: how emails get in (files, Outlook), including throwing away hidden text.
   **`ListRules.cs`**, **`Accounts.cs`**, and **`Alerts.cs`**: the list rules, password storage, and alert emails.
6. **`ThresholdPicker.cs`** and **`Evaluator.cs`**: how to judge a model (precision, recall, AUC) and why the real-world scam rate matters.
7. **`OcrNoiser.cs`**: shortcut learning, and data augmentation as the fix.
8. **`ScamDetector.cs`**: using the trained model on new messages.

The rest of `ScamFilter.Core` is support code, each file explained at its top:

| File | What it does |
|---|---|
| `MessageRecord.cs`, `Verdict.cs`, `LinkInfo.cs` | The data shapes: one message, the detector's answer, one link described for people. |
| `MsgImporter.cs` | Reads Outlook `.msg` files (dragged out of classic Outlook). |
| `PdfImporter.cs` | Reads the text and the links' real targets out of PDFs, and lists the scanned pages that need OCR. |
| `NearDuplicates.cs` | Groups near-identical messages so a campaign can't sit in both training and test data. |
| `SparseVector.cs` | A list of numbers that stores only the nonzero ones (fast math on huge, mostly empty vectors). |
| `ProtectionLists.cs` | Reads and writes the Blocked and Trusted list files. |
| `Paths.cs`, `DataFiles.cs`, `SharedFiles.cs` | Where files live, reading and writing them, and keeping them safe when several windows are open. |
| `Format.cs`, `JavaRandom.cs` | Numbers that print the same on every PC, and Java's random number generator. |

### The app (`ScamFilter.Desktop`)

Each window is two files: the layout (`.xaml`, like HTML) and the code that reacts to it (`.xaml.cs`). The main window is big, so its code is split by page into several files of one class (a C# "partial class").

| File | What it does |
|---|---|
| `App.xaml.cs` | Startup: data folder, built-in model, which account window to show, `--developer` and `--self-test`. |
| `AccountWindow` | First run, sign-in, and choosing an account. Ctrl+Shift+D opens the developer environment. |
| `MainWindow.xaml` / `.xaml.cs` | The layout of every page; the Check page (paste, upload, drop, results), History, and training on the Model page. |
| `MainWindow.Outlook.cs` | The Outlook page (a developer tab for now): linking an account and checking its newest emails. |
| `MainWindow.Protections.cs` | The Blocked and Trusted lists, alerts, and the password lock on anything that weakens protection. |
| `MainWindow.Account.cs` | The Account page: password, recovery code, switching and removing accounts. |
| `MainWindow.Developer.cs` | The developer tabs: the AI viewer and the Developer page. |
| `MainWindow.SelfTest.cs` | The `--self-test` check of every page and dialog, plus pasting a screenshot and uploading pictures and a PDF, with Windows' real OCR. |
| `UnlockDialog`, `CodeDialog`, `InputDialog` | The password prompt, the recovery-code display, and the name/password prompt. |
| `AlertService.cs` | Sends alert emails through the account's linked Outlook. |
| `OutlookAccount.cs` | Signing in to Microsoft and keeping the sign-in (the app's registration ID lives here). |
| `OutlookDrop.cs`, `AsyncDrop.cs`, `ClipboardHelper.cs`, `OcrService.cs` | Getting messages in: emails and attachments dragged from Outlook (classic, and the new one, which needs the "asynchronous" handshake in `AsyncDrop.cs`), the clipboard (text, HTML, and pictures in every form Windows copies them), and text read from screenshots, photos and scanned PDF pages. |
| `HistoryItem.cs`, `OutlookItem.cs` | One row on the History and Outlook pages. |
| `Theme.xaml` | Colors, fonts, and the look of buttons and boxes. |

### The trainer (`ScamFilter.Trainer`)

| File | What it does |
|---|---|
| `Program.cs` | The commands: train (the default), `demo`, `help`, and the dataset tools. |
| `DatasetTools.cs` | Turns public datasets and the example-message files into `records.jsonl` lines, and applies the label fixes. |

### Ported from Java

The backend started as a line-for-line port of the original Java (BlueJ) version. `JavaRandom.cs` reproduces Java's random number generator exactly, so both versions make identical splits and shuffles. On the same data, version 1.0 produced the same training report, the same verdicts, and model weights matching the Java version's to within 1e-16. Since then the C# version has gained fixes the Java one doesn't have (Safe Links unwrapping, fewer brand false positives, hidden-character handling).

## Training data

`data\records.jsonl` holds 19,152 labeled messages: text messages (normal, spam, and smishing), phishing emails from 2019 to 2026 (including a honeypot collection labeled for this project), advance-fee fraud, normal emails from mailing lists and other mailboxes, and 1,023 modern example messages written for this project (ads, verification emails, college marketing, receipts, school and work mail, and the scams that copy them). [`data\SOURCES.md`](data/SOURCES.md) says where each part comes from, its license (**one part is non-commercial only**), how it was labeled and cleaned, and how to rebuild it.

**How well it does** (the built-in model in version 1.5.4, on 2,720 test messages it never trained on, split so near-copies of a message can't be on both sides):

| | Texts | Emails |
|---|---|---|
| Right at a 50% cut-off | **97.3%** | **98.3%** |
| Scams caught (not called *Safe*) | 98.2% | 99.1% |
| Variety check: example messages never trained on (optimistic: same author as the training examples) | 91.7% | 85.9% |

Overall AUC 0.997; 3 of 1,920 legit test messages (0.16%) were called *Unsafe*. The goal was 99.5% and this is short of it: SOURCES.md explains where the misses are (mostly texts whose public labels can be read either way, honeypot emails built to dodge filters, and short money notices like "Your direct deposit arrived"). These numbers are lower than version 1.2's 98.4% overall partly because the test got harder and fairer: newer and more varied emails, and a split that keeps near-duplicate messages out of the test. Marking real results in the app is the best fix: corrections always go into training, and each counts five times.

Every field is optional except `body_text` and `label`. A missing field means *unknown*, and unknown counts as neutral.

```json
{
  "type": "email",
  "sender": "support@paypa1-secure.com",
  "display_name": "PayPal Support",
  "subject": "Account suspended",
  "body_text": "visible text, INCLUDING the visible text of links",
  "image_text": "text read out of images",
  "urls": [{ "display": "paypal.com/login", "href": "http://paypa1-secure.com/x" }],
  "auth": { "spf": "pass", "dkim": "none", "dmarc": "fail" },
  "sender_is_contact": false,
  "label": 1,
  "source": "nazario_2024",
  "channel": "raw"
}
```

The fields with fixed values:
- `type`: `"email"` or `"text"`.
- `label`: `1` means scam and `0` means not scam. Marketing spam counts as `0`.
- `channel`: `"raw"` or `"ocr"`.

**Adding a dataset:** import it with the trainer (`import-csv`, `import-mbox`, or `import-dir`; see `-- help`), give it its own `source` name, and train again. The report's *By source* table shows how the model does on each one.

## Download

The ready-to-run `ScamFilter.exe` is on the [Releases](../../releases) page. It's one self-contained file for 64-bit Windows 10 or 11; nothing else needs installing.

## License

Code: MIT (see `LICENSE`). Training data and the trained model: see [`data/SOURCES.md`](data/SOURCES.md). Part of the data (Phishing Pot) is CC BY-NC 4.0, so the data and the model are for non-commercial use.
