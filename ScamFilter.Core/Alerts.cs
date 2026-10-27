using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ScamFilter
{
    /*
     * ALERTS: emailing a trusted person (a parent, say) when something worrying happens.
     *
     * What's in this file, in the order an alert travels:
     *
     *   AlertSettings    who gets alerts and for what (saved per account as alerts.json)
     *   Alert            one alert email: what kind, subject, body
     *   AlertComposer    writes the email text (plain text, no clickable links)
     *   AlertLog         remembers what was sent, holds what's waiting, enforces the hourly limit
     *   Json             small helpers for reading and writing the settings file
     *
     * The sending itself happens in the app (ScamFilter.Desktop/AlertService.cs), through the
     * account's linked Outlook, because sending mail needs a signed-in Microsoft account.
     */

    // Someone to email when something goes wrong.
    public class AlertContact
    {
        public string Name = "";    // what the alert email calls them ("Mom")
        public string Email = "";   // where alerts are sent
    }

    /*
     * An account's alert settings (alerts.json in the account's folder): who gets emailed, and
     * for what. All three triggers start turned on.
     */
    public class AlertSettings
    {
        // At most this many people get alerts (enough for family, few enough to stay personal).
        public const int MaxContacts = 3;

        public List<AlertContact> Contacts = new List<AlertContact>();   // who gets the alerts
        public bool OnUnsafe = true;                                     // a message came out Unsafe
        public bool OnWrongPassword = true;                              // the wrong password was entered 5 times in a row
        public bool OnProtectionChange = true;                           // something was trusted, unblocked, or turned off

        // Where an account's alert settings are saved.
        public static string PathFor(string accountFolder)
        {
            return Path.Combine(accountFolder, "alerts.json");
        }

        // Reads an account's settings, or the defaults (everything on, nobody to tell) if there's no file.
        public static AlertSettings Load(string accountFolder)
        {
            AlertSettings s = new AlertSettings();
            string path = PathFor(accountFolder);
            if (!File.Exists(path))
            {
                return s;
            }
            JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
            try
            {
                JsonElement root = doc.RootElement;
                JsonElement list;
                if (root.TryGetProperty("contacts", out list) && list.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement c in list.EnumerateArray())
                    {
                        AlertContact contact = new AlertContact();
                        contact.Name = Json.Str(c, "name");
                        contact.Email = Json.Str(c, "email");
                        if (contact.Email.Length > 0)
                        {
                            s.Contacts.Add(contact);
                        }
                    }
                }
                s.OnUnsafe = Json.Bool(root, "onUnsafe", true);
                s.OnWrongPassword = Json.Bool(root, "onWrongPassword", true);
                s.OnProtectionChange = Json.Bool(root, "onProtectionChange", true);
            }
            finally
            {
                doc.Dispose();
            }
            return s;
        }

        // Writes the settings back to alerts.json.
        public void Save(string accountFolder)
        {
            Directory.CreateDirectory(accountFolder);
            MemoryStream buffer = new MemoryStream();
            Utf8JsonWriter w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true });
            w.WriteStartObject();
            w.WriteStartArray("contacts");
            foreach (AlertContact c in Contacts)
            {
                w.WriteStartObject();
                w.WriteString("name", c.Name);
                w.WriteString("email", c.Email);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteBoolean("onUnsafe", OnUnsafe);
            w.WriteBoolean("onWrongPassword", OnWrongPassword);
            w.WriteBoolean("onProtectionChange", OnProtectionChange);
            w.WriteEndObject();
            w.Flush();
            w.Dispose();
            SharedFiles.WriteAtomically(PathFor(accountFolder), buffer.ToArray());
            buffer.Close();
        }

        /*
         * Checks a new contact. Returns why it's refused, or null. The email address goes through
         * the same reader as the lists, so "Mom@Gmail.com " and "mom@gmail.com" are the same.
         */
        public string WhyContactNotAllowed(string name, string email, IEnumerable<string> ownAddresses, out string cleanEmail)
        {
            cleanEmail = "";
            if (Contacts.Count >= MaxContacts)
            {
                return "You can have up to " + MaxContacts + " alert contacts.";
            }
            string n = (name ?? "").Trim();
            if (n.Length == 0)
            {
                return "Type their name, so the alert can say who it's for.";
            }
            if (n.Length > 40)
            {
                return "Keep the name to 40 characters or fewer.";
            }
            ListRules.Result parsed = ListRules.Parse(email);
            if (!parsed.Ok || parsed.Entry.Kind != EntryKind.Email)
            {
                return "Type their email address, like name@example.com. (Text-message alerts aren't available yet.)";
            }
            cleanEmail = parsed.Entry.Value;
            foreach (string own in ownAddresses)
            {
                if (own != null && own.Trim().ToLowerInvariant() == cleanEmail)
                {
                    return "That's your own address. Alerts are for someone else you trust, like a family member.";
                }
            }
            foreach (AlertContact c in Contacts)
            {
                if (c.Email == cleanEmail)
                {
                    return cleanEmail + " is already an alert contact.";
                }
            }
            return null;
        }

        // A fingerprint of these settings, for the protection fingerprint (see Account).
        public string Describe()
        {
            StringBuilder sb = new StringBuilder();
            foreach (AlertContact c in Contacts)
            {
                sb.Append(c.Email).Append(';');
            }
            sb.Append(OnUnsafe).Append(OnWrongPassword).Append(OnProtectionChange);
            return sb.ToString();
        }
    }

    // What kind of alert it is.
    public enum AlertKind { Unsafe, WrongPassword, ProtectionChange, Test }

    // One alert email, ready to send.
    public class Alert
    {
        public AlertKind Kind;                          // what happened (decides which setting turns it on or off)
        public string Subject = "";                     // the email's subject line
        public string Body = "";                        // "{contact}" is replaced by each contact's name
        public string DedupeKey = "";                   // the same key is never sent twice (within 30 days)
        public DateTime CreatedUtc = DateTime.UtcNow;   // when it was made (alerts older than 2 days are dropped)

        // Who gets it, decided when the alert is made. So removing a contact still tells that
        // contact they were removed, and turning alerts off still sends the "turned off" alert.
        public List<AlertContact> Recipients = new List<AlertContact>();
    }

    /*
     * Writes the alert emails. Plain text on purpose: no links at all (the scam's own links are
     * never included, so the person reading the alert can't click one by mistake).
     */
    public static class AlertComposer
    {
        // One flagged message, as the alert describes it.
        public class Flagged
        {
            public string From = "";                            // who it claimed to be from
            public string Subject = "";                         // its subject (emails) or "" (texts)
            public DateTime WhenLocal;                          // when it was checked
            public string Where = "";                           // "in their Outlook inbox" / "checked by hand"
            public List<string> Reasons = new List<string>();   // the plain-words reasons from the verdict
            public string Key = "";                             // what makes it this message (for not alerting twice)
        }

        // "Sat, Oct 24 at 11:09 AM", for the email text.
        private static string When(DateTime local)
        {
            return local.ToString("ddd, MMM d 'at' h:mm tt", CultureInfo.InvariantCulture);
        }

        // The last lines of every alert: why the contact is getting it.
        private static string Footer(string name)
        {
            return "\n\nYou're getting this because " + name + " added you as a trusted contact in ScamFilter, "
                + "a scam checker on their computer. It never opens links, and it can only send these alerts.\n";
        }

        // "A message looked like a scam": one alert for one or more Unsafe messages.
        public static Alert Unsafe(string name, List<Flagged> messages)
        {
            Alert a = new Alert();
            a.Kind = AlertKind.Unsafe;
            a.Subject = messages.Count == 1 ? "ScamFilter: an unsafe message for " + name
                : "ScamFilter: " + messages.Count + " unsafe messages for " + name;
            StringBuilder sb = new StringBuilder();
            sb.Append("Hi {contact},\n\n");
            sb.Append("ScamFilter on " + name + "'s computer marked " + (messages.Count == 1 ? "a message" : messages.Count + " messages")
                + " as Unsafe, most likely a scam.\n");
            StringBuilder keys = new StringBuilder();
            foreach (Flagged m in messages)
            {
                sb.Append("\n");
                if (m.From.Length > 0)
                {
                    sb.Append("From:    " + NoLinks(m.From) + "\n");
                }
                if (m.Subject.Length > 0)
                {
                    sb.Append("Subject: " + NoLinks(m.Subject) + "\n");
                }
                sb.Append("When:    " + When(m.WhenLocal) + (m.Where.Length > 0 ? ", " + m.Where : "") + "\n");
                if (m.Reasons.Count > 0)
                {
                    sb.Append("Why:     " + NoLinks(string.Join("; ", m.Reasons)) + "\n");
                }
                keys.Append(m.Key).Append('|');
            }
            sb.Append("\nYou might check in with " + name + " and remind them not to click links, reply, or call any number in it.");
            sb.Append(Footer(name));
            a.Body = sb.ToString();
            a.DedupeKey = "unsafe:" + Hash(keys.ToString());
            return a;
        }

        // "Someone typed the wrong password 5 times": sent when the account locks.
        public static Alert WrongPassword(string name, int attempts, int lockMinutes, DateTime whenLocal)
        {
            Alert a = new Alert();
            a.Kind = AlertKind.WrongPassword;
            a.Subject = "ScamFilter: wrong password entered on " + name + "'s computer";
            a.Body = "Hi {contact},\n\n"
                + "On " + When(whenLocal) + ", someone entered the wrong ScamFilter password " + attempts + " times in a row on "
                + name + "'s computer. ScamFilter locked its settings for " + lockMinutes + " minutes.\n\n"
                + "If that wasn't " + name + " forgetting their password, someone may be trying to turn off their scam "
                + "protection. That's a common step in phone scams (\"let me help you fix your computer\")."
                + Footer(name);
            a.DedupeKey = "password:" + whenLocal.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture);
            return a;
        }

        // "Protections were changed": what was trusted, unblocked or turned off. outsideApp = true
        // when the files were edited without ScamFilter (found by the tripwire at start-up).
        public static Alert ProtectionChanged(string name, List<string> changes, bool outsideApp)
        {
            Alert a = new Alert();
            a.Kind = AlertKind.ProtectionChange;
            a.Subject = "ScamFilter: " + name + "'s protection settings were changed";
            StringBuilder sb = new StringBuilder();
            sb.Append("Hi {contact},\n\n");
            if (outsideApp)
            {
                sb.Append("ScamFilter found that its protection files on " + name + "'s computer were changed without using "
                    + "ScamFilter (edited directly on disk). That's unusual.\n");
            }
            else
            {
                sb.Append("These changes were made to ScamFilter's protection settings on " + name + "'s computer:\n");
            }
            foreach (string change in changes)
            {
                sb.Append("  - " + NoLinks(change) + "\n");
            }
            sb.Append("\nIf " + name + " didn't mean to make these changes, someone may have talked them into it. "
                + "Scammers often ask people to \"trust\" their number or turn off warnings.");
            sb.Append(Footer(name));
            a.Body = sb.ToString();
            a.DedupeKey = "change:" + Hash(string.Join("\n", changes) + DateTime.UtcNow.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture));
            return a;
        }

        // A test alert, sent from the Protections page to check that alerts arrive.
        public static Alert Test(string name)
        {
            Alert a = new Alert();
            a.Kind = AlertKind.Test;
            a.Subject = "ScamFilter: test alert from " + name;
            a.Body = "Hi {contact},\n\n"
                + "This is a test. " + name + " set you up to get an email from ScamFilter if a scam message shows up on their "
                + "computer, if someone keeps entering the wrong ScamFilter password, or if their protection settings change. "
                + "Nothing's wrong right now." + Footer(name);
            a.DedupeKey = "test:" + Guid.NewGuid().ToString("N");
            return a;
        }

        /*
         * Breaks up anything that looks like a link or email address, so email apps don't turn
         * it into something clickable: "pay-now.top/x" -> "pay-now[.]top/x". (The same trick
         * security teams use when they share scam links.)
         */
        public static string NoLinks(string s)
        {
            string t = (s ?? "").Replace("http://", "hxxp://").Replace("https://", "hxxps://")
                .Replace("HTTP://", "hxxp://").Replace("HTTPS://", "hxxps://");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < t.Length; i++)
            {
                char c = t[i];
                bool betweenLetters = c == '.' && i > 0 && i + 1 < t.Length
                    && char.IsLetterOrDigit(t[i - 1]) && char.IsLetter(t[i + 1]);
                sb.Append(betweenLetters ? "[.]" : c.ToString());
            }
            return sb.ToString();
        }

        // A short SHA-256 fingerprint of a text, used to make dedupe keys.
        private static string Hash(string s)
        {
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).Substring(0, 24);
        }
    }

    /*
     * The record of alerts: what was sent (so nothing's sent twice), what's waiting (no internet,
     * say), and a limit of MaxPerHour per account, so a flood of scam emails can't become a
     * flood of alerts. Kept in the account folder as alerts_sent.txt and alerts_waiting.jsonl.
     *
     * The same account can be open in two ScamFilter windows, so every change re-reads the
     * files, makes the change, and writes them back while holding alerts.lock (see FileLock).
     * That way neither window undoes the other's changes.
     */
    public class AlertLog
    {
        // At most this many alerts go out per hour, per account.
        public const int MaxPerHour = 10;
        // How long a sent alert's key is remembered (so it isn't sent again).
        private static readonly TimeSpan KeepKeys = TimeSpan.FromDays(30);

        private readonly string folder;
        // dedupe key -> when that alert was sent
        private readonly Dictionary<string, DateTime> sent = new Dictionary<string, DateTime>();
        // Alerts made but not sent yet (no internet, Outlook not linked, ...), oldest first.
        public readonly List<Alert> Waiting = new List<Alert>();

        public AlertLog(string accountFolder)
        {
            folder = accountFolder;
            Reload();
        }

        private string LockPath
        {
            get { return Path.Combine(folder, "alerts.lock"); }
        }

        // Reads both files again (another window may have changed them).
        public void Reload()
        {
            FileLock held = FileLock.Acquire(LockPath, TimeSpan.FromSeconds(10));
            try
            {
                ReadFiles();
            }
            finally
            {
                if (held != null)
                {
                    held.Release();
                }
            }
        }

        // Fills `sent` and `Waiting` from the two files (called while holding the lock).
        private void ReadFiles()
        {
            sent.Clear();
            Waiting.Clear();
            string sentPath = Path.Combine(folder, "alerts_sent.txt");
            if (File.Exists(sentPath))
            {
                foreach (string line in File.ReadAllLines(sentPath))
                {
                    string[] parts = line.Split('\t');
                    DateTime when;
                    if (parts.Length == 2 && DateTime.TryParse(parts[1], CultureInfo.InvariantCulture,
                            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out when)
                        && DateTime.UtcNow - when < KeepKeys)
                    {
                        sent[parts[0]] = when;
                    }
                }
            }
            string waitingPath = Path.Combine(folder, "alerts_waiting.jsonl");
            if (File.Exists(waitingPath))
            {
                foreach (string line in File.ReadAllLines(waitingPath))
                {
                    Alert a = FromJson(line);
                    if (a != null)
                    {
                        Waiting.Add(a);
                    }
                }
            }
        }

        // Re-read, change, write back, all while holding the lock.
        private void Change(Action change)
        {
            Directory.CreateDirectory(folder);
            FileLock held = FileLock.Acquire(LockPath, TimeSpan.FromSeconds(10));
            try
            {
                ReadFiles();
                change();
                WriteFiles();
            }
            finally
            {
                if (held != null)
                {
                    held.Release();
                }
            }
        }

        // Was an alert with this key sent in the last 30 days?
        public bool AlreadySent(string key)
        {
            return sent.ContainsKey(key);
        }

        // Is an alert with this key waiting to be sent?
        public bool IsWaiting(string key)
        {
            foreach (Alert w in Waiting)
            {
                if (w.DedupeKey == key)
                {
                    return true;
                }
            }
            return false;
        }

        // How many were sent in the last hour.
        public int SentLastHour(DateTime nowUtc)
        {
            int n = 0;
            foreach (DateTime when in sent.Values)
            {
                if (nowUtc - when < TimeSpan.FromHours(1))
                {
                    n++;
                }
            }
            return n;
        }

        // Adds an alert to the waiting list, unless the same one was already sent or is waiting.
        public void Queue(Alert a)
        {
            Change(() =>
            {
                if (!AlreadySent(a.DedupeKey) && !IsWaiting(a.DedupeKey))
                {
                    Waiting.Add(a);
                }
            });
        }

        // Records that an alert went out, and takes it off the waiting list.
        public void MarkSent(Alert a, DateTime nowUtc)
        {
            Change(() =>
            {
                sent[a.DedupeKey] = nowUtc;
                Waiting.RemoveAll(w => w.DedupeKey == a.DedupeKey);
            });
        }

        // Alerts that sat waiting for more than 2 days are dropped: old news by then.
        public void DropStale(DateTime nowUtc)
        {
            Change(() => Waiting.RemoveAll(a => nowUtc - a.CreatedUtc > TimeSpan.FromDays(2)));
        }

        // Writes both files as they are in memory.
        public void Save()
        {
            FileLock held = FileLock.Acquire(LockPath, TimeSpan.FromSeconds(10));
            try
            {
                WriteFiles();
            }
            finally
            {
                if (held != null)
                {
                    held.Release();
                }
            }
        }

        // Writes alerts_sent.txt and alerts_waiting.jsonl (called while holding the lock).
        private void WriteFiles()
        {
            Directory.CreateDirectory(folder);
            StringBuilder s = new StringBuilder();
            foreach (KeyValuePair<string, DateTime> e in sent)
            {
                s.Append(e.Key).Append('\t').Append(e.Value.ToString("o", CultureInfo.InvariantCulture)).Append('\n');
            }
            SharedFiles.WriteAtomically(Path.Combine(folder, "alerts_sent.txt"), s.ToString());
            StringBuilder w = new StringBuilder();
            foreach (Alert a in Waiting)
            {
                w.Append(ToJson(a)).Append('\n');
            }
            SharedFiles.WriteAtomically(Path.Combine(folder, "alerts_waiting.jsonl"), w.ToString());
        }

        // One waiting alert as one line of JSON.
        private static string ToJson(Alert a)
        {
            MemoryStream buffer = new MemoryStream();
            Utf8JsonWriter w = new Utf8JsonWriter(buffer);
            w.WriteStartObject();
            w.WriteString("kind", a.Kind.ToString());
            w.WriteString("subject", a.Subject);
            w.WriteString("body", a.Body);
            w.WriteString("key", a.DedupeKey);
            w.WriteString("created", a.CreatedUtc.ToString("o", CultureInfo.InvariantCulture));
            w.WriteStartArray("to");
            foreach (AlertContact c in a.Recipients)
            {
                w.WriteStartObject();
                w.WriteString("name", c.Name);
                w.WriteString("email", c.Email);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
            w.Flush();
            w.Dispose();
            string json = Encoding.UTF8.GetString(buffer.ToArray());
            buffer.Close();
            return json;
        }

        // The other direction from ToJson. Returns null for a damaged line or one with no recipients.
        private static Alert FromJson(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                return null;
            }
            try
            {
                JsonDocument doc = JsonDocument.Parse(line);
                try
                {
                    Alert a = new Alert();
                    AlertKind kind;
                    a.Kind = Enum.TryParse(Json.Str(doc.RootElement, "kind"), out kind) ? kind : AlertKind.Unsafe;
                    a.Subject = Json.Str(doc.RootElement, "subject");
                    a.Body = Json.Str(doc.RootElement, "body");
                    a.DedupeKey = Json.Str(doc.RootElement, "key");
                    DateTime when;
                    a.CreatedUtc = DateTime.TryParse(Json.Str(doc.RootElement, "created"), CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out when) ? when : DateTime.UtcNow;
                    JsonElement to;
                    if (doc.RootElement.TryGetProperty("to", out to) && to.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement c in to.EnumerateArray())
                        {
                            AlertContact contact = new AlertContact();
                            contact.Name = Json.Str(c, "name");
                            contact.Email = Json.Str(c, "email");
                            a.Recipients.Add(contact);
                        }
                    }
                    return a.DedupeKey.Length > 0 && a.Recipients.Count > 0 ? a : null;
                }
                finally
                {
                    doc.Dispose();
                }
            }
            catch (JsonException)
            {
                return null;   // a damaged line is skipped
            }
        }
    }

    // Small JSON helpers shared by the settings files.
    public static class Json
    {
        // A string property of a JSON object, or "" if it's missing.
        public static string Str(JsonElement e, string name)
        {
            JsonElement value;
            if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }
            return "";
        }

        // A true/false property of a JSON object, or `fallback` if it's missing.
        public static bool Bool(JsonElement e, string name, bool fallback)
        {
            JsonElement value;
            if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out value)
                && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
            {
                return value.GetBoolean();
            }
            return fallback;
        }
    }
}
