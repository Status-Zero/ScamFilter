using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using MimeKit;
using ScamFilter;

namespace ScamFilter.TrainerApp
{
    /*
     * Turns public datasets into training records (one JSON object per line in records.jsonl).
     * Nothing AI here: it reads files, cleans them, and writes records. The emails go through
     * the same EmlImporter the app uses, so the model is trained on messages read exactly the
     * way the app will read them later.
     *
     * Three input formats:
     *   mbox   a mailbox file: many emails one after another (the Nazario phishing corpus,
     *          mailing-list archives)
     *   dir    a folder with one email per file (the SpamAssassin corpus, saved .eml files)
     *   csv    a spreadsheet with one message per row: texts (SMS datasets), or emails when
     *          it has subject and sender columns (--type email --subject-column ... --sender-column ...)
     *
     * ============================================================================
     *  CLEANING: REMOVING SHORTCUTS
     * ============================================================================
     * A model learns whatever separates the two piles most easily. If every phishing email in
     * the data was sent to "jose@monkey.org" (the inbox the Nazario corpus came from), the
     * model learns "mentions jose = scam", scores great on the same data, and is useless on
     * your inbox. The same goes for mailing-list footers ("To unsubscribe, e-mail...") that
     * only legit emails in the data have. So the importer:
     *   - replaces corpus-specific words (--scrub "jose=you,monkey.org=example.com")
     *   - cuts mailing-list footers off the end of emails
     *   - can drop the sender's address (--anonymize), which also keeps real people's
     *     addresses out of the published data
     *   - skips duplicates, so the same message can't end up in both training and test data
     */
    public static class DatasetTools
    {
        // Everything the import commands can be told on the command line (see PrintUsage).
        public class ImportOptions
        {
            public string Source = "";         // dataset name, saved in each record
            public int Label = -1;             // 1 = scam, 0 = not scam (mbox/dir)
            public string Type = "email";      // "email" or "text"
            public int Limit = int.MaxValue;   // most records to add from this input
            public bool Anonymize = false;     // drop sender address and name
            // "old=new" replacements (see --scrub)
            public List<KeyValuePair<string, string>> Scrub = new List<KeyValuePair<string, string>>();
            public string Out = "data/records.jsonl";   // the records file to add to
            public string TextColumn = "TEXT";       // csv only
            public string LabelColumn = "LABEL";     // csv only
            public Dictionary<string, int> LabelMap = new Dictionary<string, int>();   // csv: "ham" -> 0, ...
            public List<Regex> ScamPatterns = new List<Regex>();   // csv: relabel matching rows as scams...
            public string ScamPatternsFor = "";                    // ...but only rows with this original label
            public string SubjectColumn = "";        // csv emails: column with the subject line
            public string SenderColumn = "";         // csv emails: column with the From address
            public Regex ExcludeSubject = null;      // csv emails: skip rows whose subject matches
            public int PerSenderLimit = int.MaxValue;   // csv emails: at most this many per sender domain

            // dir only: a label for each file, read from a list made by a person (--labels FILE).
            // Files not on the list are skipped. See data/import/phishing_pot_labels.tsv.
            public Dictionary<string, int> FileLabels = null;

            // A shallow copy, so one file's label can differ from the rest.
            public ImportOptions MemberwiseCloneOptions()
            {
                return (ImportOptions) MemberwiseClone();
            }
        }

        // Body text is cut to this length in the saved record (the model reads less than this anyway).
        private const int MaxBodyChars = 2500;

        // Messages with less text than this carry no usable evidence (blank or image-only).
        private const int MinTextChars = 20;

        // ------------------------------------------------------------------
        // Command line:  import-mbox | import-dir | import-csv  <path>  [options]
        // ------------------------------------------------------------------

        public static int Run(string command, string[] args)
        {
            if (command == "fix-conflicts")
            {
                return FixConflicts(args);
            }
            if (command == "fix-labels")
            {
                return FixLabels(args);
            }
            if (command == "import-variety")
            {
                return ImportVariety(args);
            }
            if (args.Length < 2)
            {
                PrintUsage();
                return 1;
            }
            string path = args[1];
            ImportOptions o = ParseOptions(args, 2);
            if (o.Source.Length == 0)
            {
                Console.WriteLine("--source is required (a short name for this dataset, like nazario_2024).");
                return 1;
            }
            HashSet<string> seen = LoadExistingKeys(o.Out);
            int added;
            if (command == "import-mbox")
            {
                added = ImportMbox(path, o, seen);
            }
            else if (command == "import-dir")
            {
                added = ImportDirectory(path, o, seen);
            }
            else
            {
                added = ImportCsv(path, o, seen);
            }
            Console.WriteLine("Added " + added + " records from " + path + " to " + o.Out);
            return 0;
        }

        // The help text for the dataset commands.
        public static void PrintUsage()
        {
            Console.WriteLine("Dataset import commands (they append to data/records.jsonl, skipping duplicates):");
            Console.WriteLine("  import-mbox <file.mbox> --source NAME --label 0|1 [--scrub old=new,...] [--anonymize] [--limit N]");
            Console.WriteLine("  import-dir  <folder>    --source NAME --label 0|1 [--scrub old=new,...] [--anonymize] [--limit N]");
            Console.WriteLine("              [--labels FILE]   one line per file: name<TAB>0|1<TAB>note; only listed files are imported");
            Console.WriteLine("  import-csv  <file.csv>  --source NAME --map ham=0,spam=0,smishing=1 [--text-column TEXT] [--label-column LABEL] [--type text]");
            Console.WriteLine("              [--scam-patterns FILE --scam-patterns-for LABEL]   rows with that original label whose text");
            Console.WriteLine("              matches a pattern in FILE are imported as scams (see data/import/sms_scam_patterns.txt)");
            Console.WriteLine("              [--type email --subject-column subject --sender-column sender]   emails, one per row");
            Console.WriteLine("              [--exclude-subject REGEX] [--per-sender-limit N]   for variety: skip subjects, cap each sender's domain");
            Console.WriteLine("  fix-labels  <fixes.tsv> [--out FILE]   apply a reviewed list of label fixes (see data/import/label_fixes.tsv)");
            Console.WriteLine("  import-variety <file.txt> --source NAME [--out FILE]   example messages (see data/import/variety/README.md)");
            Console.WriteLine("  fix-conflicts --source NAME [--similarity 0.6] [--dry-run]   near-duplicate messages with different");
            Console.WriteLine("              labels all get the group's majority label (ties count as scam)");
        }

        // Reads "--name value" options from the command line, starting at args[start].
        private static ImportOptions ParseOptions(string[] args, int start)
        {
            ImportOptions o = new ImportOptions();
            for (int i = start; i < args.Length; i++)
            {
                string a = args[i];
                string next = i + 1 < args.Length ? args[i + 1] : "";
                switch (a)
                {
                    case "--source": o.Source = next; i++; break;
                    case "--label": o.Label = int.Parse(next); i++; break;
                    case "--type": o.Type = next; i++; break;
                    case "--limit": o.Limit = int.Parse(next); i++; break;
                    case "--out": o.Out = next; i++; break;
                    case "--anonymize": o.Anonymize = true; break;
                    case "--text-column": o.TextColumn = next; i++; break;
                    case "--scam-patterns-for": o.ScamPatternsFor = next.Trim().ToLowerInvariant(); i++; break;
                    case "--scam-patterns":
                        foreach (string pattern in DataFiles.ReadList(next))
                        {
                            o.ScamPatterns.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                        }
                        i++;
                        break;
                    case "--label-column": o.LabelColumn = next; i++; break;
                    case "--subject-column": o.SubjectColumn = next; i++; break;
                    case "--sender-column": o.SenderColumn = next; i++; break;
                    case "--exclude-subject": o.ExcludeSubject = new Regex(next, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant); i++; break;
                    case "--per-sender-limit": o.PerSenderLimit = int.Parse(next); i++; break;
                    case "--labels": o.FileLabels = ReadFileLabels(next); i++; break;
                    case "--scrub":
                        foreach (string pair in next.Split(','))
                        {
                            int eq = pair.IndexOf('=');
                            if (eq > 0)
                            {
                                o.Scrub.Add(new KeyValuePair<string, string>(pair.Substring(0, eq), pair.Substring(eq + 1)));
                            }
                        }
                        i++;
                        break;
                    case "--map":
                        foreach (string pair in next.Split(','))
                        {
                            int eq = pair.IndexOf('=');
                            if (eq > 0)
                            {
                                o.LabelMap[pair.Substring(0, eq).Trim().ToLowerInvariant()] = int.Parse(pair.Substring(eq + 1));
                            }
                        }
                        i++;
                        break;
                    default:
                        Console.WriteLine("(ignoring unknown option " + a + ")");
                        break;
                }
            }
            return o;
        }

        // ------------------------------------------------------------------
        // The three formats
        // ------------------------------------------------------------------

        /*
         * An mbox file is emails one after another, each starting with a line like
         * "From someone@example.com Mon Jan  1 00:00:00 2024" right after a blank line.
         * The file is split at those lines here, and each email is parsed on its own, so one
         * malformed email only loses that email. (Letting the library read the whole mailbox in
         * one go stops at the first broken email, losing everything after it.)
         *
         * The file is read as Latin-1, which maps every byte to one character and back
         * unchanged, so emails in any encoding reach the email parser byte-for-byte.
         */
        public static int ImportMbox(string file, ImportOptions o, HashSet<string> seen)
        {
            int added = 0;
            int unreadable = 0;
            StreamReader reader = new StreamReader(file, Encoding.Latin1);
            StreamWriter output = OpenOutput(o.Out);
            try
            {
                StringBuilder current = new StringBuilder();
                bool previousBlank = true;
                string line = reader.ReadLine();
                while (line != null && added < o.Limit)
                {
                    if (previousBlank && line.StartsWith("From ", StringComparison.Ordinal))
                    {
                        if (TryAddRawEmail(current.ToString(), o, seen, output, ref unreadable))
                        {
                            added++;
                        }
                        current.Clear();   // the "From " envelope line itself isn't part of the email
                    }
                    else
                    {
                        current.Append(line).Append('\n');
                    }
                    previousBlank = line.Length == 0;
                    line = reader.ReadLine();
                }
                if (added < o.Limit && TryAddRawEmail(current.ToString(), o, seen, output, ref unreadable))
                {
                    added++;
                }
            }
            finally
            {
                output.Close();
                reader.Close();
            }
            if (unreadable > 0)
            {
                Console.WriteLine("(skipped " + unreadable + " emails the parser couldn't read)");
            }
            return added;
        }

        // Reads one email out of an mbox file and adds it (counting the ones that can't be read).
        private static bool TryAddRawEmail(string raw, ImportOptions o, HashSet<string> seen, StreamWriter output, ref int unreadable)
        {
            if (raw.Trim().Length == 0)
            {
                return false;
            }
            MemoryStream stream = new MemoryStream(Encoding.Latin1.GetBytes(raw));
            try
            {
                return AddEmail(MimeMessage.Load(stream), o, seen, output);
            }
            catch (FormatException)
            {
                unreadable++;
                return false;
            }
            finally
            {
                stream.Close();
            }
        }

        // import-dir: every file in a folder (and its subfolders) is one email.
        public static int ImportDirectory(string folder, ImportOptions o, HashSet<string> seen)
        {
            int added = 0;
            string[] files = Directory.GetFiles(folder, "*", SearchOption.AllDirectories);
            Array.Sort(files, StringComparer.Ordinal);   // same order every run
            StreamWriter output = OpenOutput(o.Out);
            try
            {
                foreach (string file in files)
                {
                    if (added >= o.Limit)
                    {
                        break;
                    }
                    if (Path.GetFileName(file).StartsWith("cmds", StringComparison.Ordinal))
                    {
                        continue;   // SpamAssassin's index file, not an email
                    }
                    ImportOptions forFile = o;
                    if (o.FileLabels != null)
                    {
                        // With a label list, each file gets the label a person gave it, and files
                        // nobody labeled (unclear, another language, not an email) are left out.
                        int fileLabel;
                        if (!o.FileLabels.TryGetValue(Path.GetFileName(file), out fileLabel))
                        {
                            continue;
                        }
                        forFile = o.MemberwiseCloneOptions();
                        forFile.Label = fileLabel;
                    }
                    try
                    {
                        if (AddEmail(MimeMessage.Load(file), forFile, seen, output))
                        {
                            added++;
                        }
                    }
                    catch (FormatException)
                    {
                        // not an email; skip it
                    }
                }
            }
            finally
            {
                output.Close();
            }
            return added;
        }

        // import-csv: one message per row of a spreadsheet (texts, or emails with subject and sender columns).
        public static int ImportCsv(string file, ImportOptions o, HashSet<string> seen)
        {
            List<string[]> rows = ReadCsv(File.ReadAllText(file, Encoding.UTF8));
            if (rows.Count == 0)
            {
                return 0;
            }
            int textIndex = Array.IndexOf(rows[0], o.TextColumn);
            int labelIndex = Array.IndexOf(rows[0], o.LabelColumn);
            int subjectIndex = o.SubjectColumn.Length > 0 ? Array.IndexOf(rows[0], o.SubjectColumn) : -1;
            int senderIndex = o.SenderColumn.Length > 0 ? Array.IndexOf(rows[0], o.SenderColumn) : -1;
            if (textIndex < 0 || labelIndex < 0 || (o.SubjectColumn.Length > 0 && subjectIndex < 0)
                || (o.SenderColumn.Length > 0 && senderIndex < 0))
            {
                Console.WriteLine("Columns not found. The header row is: " + string.Join(" | ", rows[0]));
                return 0;
            }
            int added = 0;
            int unmapped = 0;
            int relabeled = 0;
            Dictionary<string, int> perSender = new Dictionary<string, int>();
            StreamWriter output = OpenOutput(o.Out);
            try
            {
                for (int i = 1; i < rows.Count && added < o.Limit; i++)
                {
                    string[] row = rows[i];
                    if (row.Length <= Math.Max(textIndex, labelIndex))
                    {
                        continue;
                    }
                    int label;
                    if (!o.LabelMap.TryGetValue(row[labelIndex].Trim().ToLowerInvariant(), out label))
                    {
                        unmapped++;
                        continue;
                    }
                    MessageRecord r = new MessageRecord();
                    r.Type = o.Type == "email" ? "email" : "text";
                    r.BodyText = Clean(row[textIndex], o);
                    if (r.IsEmail())
                    {
                        string subject = subjectIndex >= 0 && subjectIndex < row.Length ? row[subjectIndex] : "";
                        if (o.ExcludeSubject != null && o.ExcludeSubject.IsMatch(subject))
                        {
                            continue;
                        }
                        r.Subject = Clean(subject, o);
                        r.BodyText = Clean(StripListFooter(row[textIndex]), o);
                        if (senderIndex >= 0 && senderIndex < row.Length && !o.Anonymize)
                        {
                            SplitSender(row[senderIndex], r);
                            r.Sender = Clean(r.Sender, o);
                            r.DisplayName = Clean(r.DisplayName, o);
                        }
                        // The spreadsheet has the email's text but not its HTML, so the links are
                        // whatever web addresses appear in the text (where they show = where they go).
                        foreach (string link in UrlAnalyzer.ExtractUrls(r.BodyText))
                        {
                            if (r.Urls.Count < 20)
                            {
                                r.Urls.Add(new MessageRecord.UrlRef(link, link));
                            }
                        }
                        string domain = senderIndex >= 0 && senderIndex < row.Length ? SenderDomain(row[senderIndex]) : "";
                        int count;
                        perSender.TryGetValue(domain, out count);
                        if (count >= o.PerSenderLimit)
                        {
                            continue;
                        }
                        perSender[domain] = count + 1;
                    }
                    if (label == 0 && o.ScamPatterns.Count > 0
                        && row[labelIndex].Trim().ToLowerInvariant() == o.ScamPatternsFor && MatchesAny(o.ScamPatterns, r.BodyText))
                    {
                        label = 1;   // a scam tactic, even though the dataset filed it under ads
                        relabeled++;
                    }
                    r.Label = label;
                    r.Source = o.Source;
                    r.Channel = "raw";
                    if (Write(r, seen, output))
                    {
                        added++;
                    }
                }
            }
            finally
            {
                output.Close();
            }
            if (unmapped > 0)
            {
                Console.WriteLine("(skipped " + unmapped + " rows whose label isn't in --map)");
            }
            if (relabeled > 0)
            {
                Console.WriteLine("(imported " + relabeled + " \"" + o.ScamPatternsFor + "\" rows as scams because they match a scam pattern)");
            }
            return added;
        }

        // "PayPal Service <service@paypal.com>"  ->  DisplayName "PayPal Service", Sender "service@paypal.com"
        private static void SplitSender(string from, MessageRecord r)
        {
            string f = (from ?? "").Trim();
            int open = f.LastIndexOf('<');
            int close = f.LastIndexOf('>');
            if (open >= 0 && close > open)
            {
                r.Sender = f.Substring(open + 1, close - open - 1).Trim();
                r.DisplayName = f.Substring(0, open).Trim().Trim('"').Trim();
            }
            else
            {
                r.Sender = f;
            }
        }

        // The domain of a From line, for --per-sender-limit ("Bob <bob@lists.example.org>" -> "example.org").
        private static string SenderDomain(string from)
        {
            MessageRecord r = new MessageRecord();
            SplitSender(from, r);
            int at = r.Sender.LastIndexOf('@');
            return at >= 0 ? r.Sender.Substring(at + 1).ToLowerInvariant() : r.Sender.ToLowerInvariant();
        }

        /*
         * A label list for import-dir --labels: one file per line,
         *     sample-123.eml<TAB>1<TAB>S1 fake Microsoft sign-in alert
         * (name, label, and an optional note saying why). Lines starting with # are comments.
         */
        private static Dictionary<string, int> ReadFileLabels(string path)
        {
            Dictionary<string, int> labels = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
            {
                if (line.Trim().Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }
                string[] parts = line.Split('\t');
                if (parts.Length >= 2 && (parts[1].Trim() == "0" || parts[1].Trim() == "1"))
                {
                    labels[parts[0].Trim()] = int.Parse(parts[1].Trim());
                }
            }
            return labels;
        }

        // ------------------------------------------------------------------
        // Conflicting near-duplicates
        // ------------------------------------------------------------------

        /*
         * Datasets often contain the same template message more than once with DIFFERENT labels:
         *   "Natalja (25/F) is inviting you to be her friend..."       labeled scam
         *   "lyricalladie (21/F) is inviting you to be her friend..."  labeled not scam
         * A model can't get both right, and every such pair costs accuracy for no reason. This
         * finds groups of near-duplicates and gives the whole group its majority label (a tie
         * counts as a scam, the safer mistake). It looks only at the messages and their labels,
         * never at what a model predicts.
         *
         * "Near-duplicate": the two messages' sets of words overlap by at least `similarity`
         * (Jaccard similarity = shared words / all words). Messages under 6 distinct words are
         * skipped, since short messages ("ok see you soon") overlap by chance.
         */
        /*
         * import-variety: reads the example message files in data/import/variety/.
         *
         * Each message is a block like this:
         *
         *     === 0 E
         *     From: Discord <noreply@discord.com>
         *     Subject: Verify Email Address for Discord
         *
         *     Hey sam_k, thanks for registering ...
         *     [Verify Email](https://click.discord.com/ls/click?upn=...)
         *
         * The "=== label type" line starts a block (label 1 = scam, 0 = not a scam; type E = email,
         * T = text). Header lines come next, then a blank line, then the body. Lines starting with
         * "# " are comments for whoever reads the file and are skipped. A link is written
         * [visible text](target), like Markdown: the visible text stays in the body (that's what
         * the reader sees) and the target goes into the record's link list (where it really goes).
         */
        private static readonly Regex VarietyLink = new Regex(@"\[([^\]]+)\]\((https?://[^)\s]+)\)");

        // The import-variety command (see the comment above).
        public static int ImportVariety(string[] args)
        {
            if (args.Length < 2)
            {
                PrintUsage();
                return 1;
            }
            ImportOptions o = ParseOptions(args, 2);
            if (o.Source.Length == 0)
            {
                Console.WriteLine("--source is required.");
                return 1;
            }
            string[] lines = File.ReadAllLines(args[1], Encoding.UTF8);
            HashSet<string> seen = LoadExistingKeys(o.Out);
            int added = 0;
            int skipped = 0;
            StreamWriter output = OpenOutput(o.Out);
            try
            {
                int i = 0;
                while (i < lines.Length)
                {
                    if (!lines[i].StartsWith("=== ", StringComparison.Ordinal))
                    {
                        i++;
                        continue;
                    }
                    string[] head = lines[i].Substring(4).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (head.Length < 2 || (head[0] != "0" && head[0] != "1") || (head[1] != "E" && head[1] != "T"))
                    {
                        throw new FormatException(args[1] + " line " + (i + 1) + ": expected \"=== 0|1 E|T\"");
                    }
                    MessageRecord r = new MessageRecord();
                    r.Label = head[0] == "1" ? 1 : 0;
                    r.Type = head[1] == "E" ? "email" : "text";
                    r.Source = o.Source;
                    i++;

                    // Header lines, up to the first blank line.
                    while (i < lines.Length && lines[i].Trim().Length > 0)
                    {
                        string line = lines[i];
                        if (line.StartsWith("From:", StringComparison.Ordinal))
                        {
                            string from = line.Substring(5).Trim();
                            if (r.IsEmail())
                            {
                                SplitSender(from, r);
                            }
                            else
                            {
                                r.Sender = from;
                            }
                        }
                        else if (line.StartsWith("Subject:", StringComparison.Ordinal))
                        {
                            r.Subject = line.Substring(8).Trim();
                        }
                        else if (line.StartsWith("Reply-To:", StringComparison.Ordinal))
                        {
                            r.ReplyTo = line.Substring(9).Trim();
                        }
                        else
                        {
                            throw new FormatException(args[1] + " line " + (i + 1) + ": unknown header \"" + line + "\"");
                        }
                        i++;
                    }

                    // The body, up to the next block.
                    StringBuilder body = new StringBuilder();
                    while (i < lines.Length && !lines[i].StartsWith("=== ", StringComparison.Ordinal))
                    {
                        if (!lines[i].StartsWith("# ", StringComparison.Ordinal))   // "# " lines are notes to the reader
                        {
                            body.Append(lines[i]).Append('\n');
                        }
                        i++;
                    }
                    string text = body.ToString().Trim();
                    foreach (Match m in VarietyLink.Matches(text))
                    {
                        r.Urls.Add(new MessageRecord.UrlRef(m.Groups[1].Value, m.Groups[2].Value));
                    }
                    r.BodyText = VarietyLink.Replace(text, "$1");
                    if (Write(r, seen, output))
                    {
                        added++;
                    }
                    else
                    {
                        skipped++;
                    }
                }
            }
            finally
            {
                output.Close();
            }
            Console.WriteLine("Added " + added + " records from " + args[1] + " to " + o.Out
                + (skipped > 0 ? " (" + skipped + " skipped as duplicates or too short)" : ""));
            return 0;
        }

        // fix-conflicts: near-duplicate messages from one source that have different labels all get
        // the group's majority label (a tie counts as a scam). See PrintUsage for the options.
        public static int FixConflicts(string[] args)
        {
            string source = "";
            double similarity = 0.6;
            bool dryRun = false;
            string path = "data/records.jsonl";
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--source" && i + 1 < args.Length) { source = args[++i]; }
                else if (args[i] == "--similarity" && i + 1 < args.Length) { similarity = double.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture); }
                else if (args[i] == "--out" && i + 1 < args.Length) { path = args[++i]; }
                else if (args[i] == "--dry-run") { dryRun = true; }
            }
            List<MessageRecord> records = MessageRecord.LoadJsonl(path);
            List<int> members = new List<int>();
            List<HashSet<string>> words = new List<HashSet<string>>();
            for (int i = 0; i < records.Count; i++)
            {
                if (records[i].Source != source || records[i].Label < 0)
                {
                    continue;
                }
                HashSet<string> set = new HashSet<string>(Regex.Split(records[i].FullText().ToLowerInvariant(), "[^a-z]+"));
                set.RemoveWhere(w => w.Length < 2);
                if (set.Count >= 6)
                {
                    members.Add(i);
                    words.Add(set);
                }
            }

            // Union-find: each message starts in its own group; similar pairs merge their groups.
            int[] parent = new int[members.Count];
            for (int i = 0; i < parent.Length; i++)
            {
                parent[i] = i;
            }
            for (int a = 0; a < members.Count; a++)
            {
                for (int b = a + 1; b < members.Count; b++)
                {
                    int shared = 0;
                    foreach (string w in words[a])
                    {
                        if (words[b].Contains(w))
                        {
                            shared++;
                        }
                    }
                    double jaccard = shared / (double) (words[a].Count + words[b].Count - shared);
                    if (jaccard >= similarity)
                    {
                        parent[Find(parent, a)] = Find(parent, b);
                    }
                }
            }

            Dictionary<int, List<int>> groups = new Dictionary<int, List<int>>();
            for (int i = 0; i < members.Count; i++)
            {
                int root = Find(parent, i);
                if (!groups.ContainsKey(root))
                {
                    groups[root] = new List<int>();
                }
                groups[root].Add(i);
            }
            int changed = 0;
            int conflictGroups = 0;
            foreach (List<int> group in groups.Values)
            {
                int scams = 0;
                foreach (int g in group)
                {
                    scams += records[members[g]].Label;
                }
                if (scams == 0 || scams == group.Count)
                {
                    continue;   // the group already agrees
                }
                conflictGroups++;
                int majority = scams * 2 >= group.Count ? 1 : 0;
                Console.WriteLine("Group of " + group.Count + " (" + scams + " scam) -> all " + (majority == 1 ? "scam" : "not scam"));
                foreach (int g in group)
                {
                    MessageRecord r = records[members[g]];
                    Console.WriteLine("   " + (r.Label != majority ? "* " : "  ") + r.Label + "  " + r.Preview(100));
                    if (r.Label != majority)
                    {
                        r.Label = majority;
                        changed++;
                    }
                }
            }
            Console.WriteLine(conflictGroups + " conflicting groups; " + changed + " labels " + (dryRun ? "would change (dry run)" : "changed"));
            if (!dryRun && changed > 0)
            {
                StreamWriter output = new StreamWriter(path, false, new UTF8Encoding(false));
                foreach (MessageRecord r in records)
                {
                    output.Write(r.ToJsonLine() + "\n");
                }
                output.Close();
            }
            return 0;
        }

        /*
         * Applies a reviewed list of label fixes. Each line of the file is
         *     source <TAB> new label <TAB> pattern <TAB> reason
         * and changes every record from that source whose text matches the pattern (a regular
         * expression, case-insensitive). The new label is 0, 1, or x ("leave it out": the record
         * stays in the file but becomes unlabeled, which training skips). Every change is printed,
         * so the file doubles as a record of what was changed and why.
         */
        public static int FixLabels(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("usage: fix-labels <fixes.tsv> [--out FILE]");
                return 1;
            }
            string path = "data/records.jsonl";
            for (int i = 2; i + 1 < args.Length; i++)
            {
                if (args[i] == "--out")
                {
                    path = args[i + 1];
                }
            }
            List<MessageRecord> records = MessageRecord.LoadJsonl(path);
            int changed = 0;
            foreach (string line in File.ReadAllLines(args[1], Encoding.UTF8))
            {
                if (line.Trim().Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }
                string[] parts = line.Split('\t');
                if (parts.Length < 3)
                {
                    continue;
                }
                string source = parts[0].Trim();
                string newLabel = parts[1].Trim();
                int label = newLabel == "1" ? 1 : (newLabel == "0" ? 0 : -1);
                Regex pattern = new Regex(parts[2], RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Multiline);
                int matched = 0;
                foreach (MessageRecord r in records)
                {
                    if (r.Source == source && pattern.IsMatch(r.FullText()))
                    {
                        matched++;
                        if (r.Label != label)
                        {
                            r.Label = label;
                            changed++;
                        }
                    }
                }
                Console.WriteLine("  " + matched.ToString().PadLeft(3) + " x " + source + " -> " + newLabel + "   " + parts[2]);
            }
            StreamWriter output = new StreamWriter(path, false, new UTF8Encoding(false));
            foreach (MessageRecord r in records)
            {
                output.Write(r.ToJsonLine() + "\n");
            }
            output.Close();
            Console.WriteLine(changed + " labels changed");
            return 0;
        }

        // Union-find, as in NearDuplicates: the group a message belongs to.
        private static int Find(int[] parent, int i)
        {
            while (parent[i] != i)
            {
                parent[i] = parent[parent[i]];   // shortcut the path as we go
                i = parent[i];
            }
            return i;
        }

        // ------------------------------------------------------------------
        // Cleaning and writing
        // ------------------------------------------------------------------

        private static bool MatchesAny(List<Regex> patterns, string text)
        {
            foreach (Regex pattern in patterns)
            {
                if (pattern.IsMatch(text))
                {
                    return true;
                }
            }
            return false;
        }

        // Turns one email into a record (cleaned and labeled) and writes it, unless it's a placeholder,
        // a duplicate, or too short. Returns true if it was added.
        private static bool AddEmail(MimeMessage message, ImportOptions o, HashSet<string> seen, StreamWriter output)
        {
            // Some mail programs store a placeholder "message" at the top of every mailbox file.
            // It isn't an email at all, so it mustn't be labeled as one.
            if ((message.Subject ?? "").StartsWith("DON'T DELETE THIS MESSAGE", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            MessageRecord r = EmlImporter.FromMessage(message).Record;
            r.Label = o.Label;
            r.Source = o.Source;
            r.Channel = "raw";
            r.Subject = Clean(r.Subject, o);
            r.BodyText = Clean(StripListFooter(r.BodyText), o);
            r.DisplayName = Clean(r.DisplayName, o);
            if (o.Anonymize)
            {
                r.Sender = "";
                r.DisplayName = "";
                r.ReplyTo = "";
            }
            else
            {
                r.Sender = Clean(r.Sender, o);
                r.ReplyTo = Clean(r.ReplyTo, o);
            }
            foreach (MessageRecord.UrlRef u in r.Urls)
            {
                u.Display = Clean(u.Display, o);
                u.Href = Clean(u.Href, o);
            }
            if (r.Urls.Count > 20)
            {
                r.Urls = r.Urls.GetRange(0, 20);   // enough to judge; keeps records small
            }
            return Write(r, seen, output);
        }

        // Cleans a piece of text: one kind of line break, the --scrub replacements (whole words,
        // ignoring case), and at most MaxBodyChars characters.
        private static string Clean(string s, ImportOptions o)
        {
            if (string.IsNullOrEmpty(s))
            {
                return "";
            }
            string t = s.Replace("\r\n", "\n").Replace('\r', '\n').Trim();
            foreach (KeyValuePair<string, string> pair in o.Scrub)
            {
                t = Regex.Replace(t, @"(?<![A-Za-z0-9])" + Regex.Escape(pair.Key) + @"(?![A-Za-z0-9])", pair.Value, RegexOptions.IgnoreCase);
            }
            if (t.Length > MaxBodyChars)
            {
                t = t.Substring(0, MaxBodyChars);
            }
            return t;
        }

        /*
         * Mailing lists add a footer to every message ("To unsubscribe, e-mail ...", "Yahoo!
         * Groups Sponsor"). Only legit emails in the data have them, which makes them a shortcut,
         * so everything from a separator line followed by footer words is cut off.
         */
        private static readonly Regex Separator = new Regex(@"^\s*(-{2,}|_{5,}|={5,}|\*{5,})\s*$");
        // Words that only appear in mailing-list footers.
        private static readonly Regex FooterWords = new Regex(
            @"unsubscribe|mailing list|list-help|yahoo! groups|listinfo|sourceforge|additional commands",
            RegexOptions.IgnoreCase);

        // Cuts a mailing-list footer off the end of an email (see above).
        private static string StripListFooter(string body)
        {
            string[] lines = body.Split('\n');
            List<string> kept = new List<string>();
            for (int i = 0; i < lines.Length; i++)
            {
                if (Separator.IsMatch(lines[i]))
                {
                    StringBuilder ahead = new StringBuilder();
                    for (int j = i + 1; j < lines.Length && j <= i + 8; j++)
                    {
                        ahead.Append(lines[j]).Append(' ');
                    }
                    if (FooterWords.IsMatch(ahead.ToString()))
                    {
                        break;
                    }
                }
                if (FooterWords.IsMatch(lines[i]) && Regex.IsMatch(lines[i], @"e-?mail:|mailto:|@", RegexOptions.IgnoreCase))
                {
                    continue;   // a single footer line like "To unsubscribe, e-mail: x@y.org"
                }
                kept.Add(lines[i]);
            }
            return string.Join("\n", kept).Trim();
        }

        // Writes the record unless it's too short or a duplicate. Returns true if written.
        private static bool Write(MessageRecord r, HashSet<string> seen, StreamWriter output)
        {
            if (r.FullText().Trim().Length < MinTextChars)
            {
                return false;
            }
            if (!seen.Add(DuplicateKey(r)))
            {
                return false;
            }
            output.Write(r.ToJsonLine() + "\n");
            return true;
        }

        /*
         * Two messages count as duplicates if their text matches after lowercasing, removing
         * digits, and collapsing spaces ("Your code is 1234" and "your code is 5678" match).
         * The key is a SHA-256 fingerprint of that, to keep memory small.
         */
        private static string DuplicateKey(MessageRecord r)
        {
            string text = Regex.Replace(r.FullText().ToLowerInvariant(), @"[0-9]", "");
            text = Regex.Replace(text, @"\s+", " ").Trim();
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        }

        // The duplicate keys of everything already in the records file, so nothing is added twice.
        private static HashSet<string> LoadExistingKeys(string path)
        {
            HashSet<string> seen = new HashSet<string>();
            if (File.Exists(path))
            {
                foreach (MessageRecord r in MessageRecord.LoadJsonl(path))
                {
                    seen.Add(DuplicateKey(r));
                }
            }
            return seen;
        }

        // Opens the records file for adding lines (making sure the last line ends first).
        private static StreamWriter OpenOutput(string path)
        {
            string folder = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }
            bool needsNewline = File.Exists(path) && new FileInfo(path).Length > 0 && !File.ReadAllText(path).EndsWith('\n');
            StreamWriter writer = new StreamWriter(path, true, new UTF8Encoding(false));
            if (needsNewline)
            {
                writer.Write("\n");
            }
            return writer;
        }

        /*
         * A small CSV reader (RFC 4180): fields are separated by commas; a field in double quotes
         * can contain commas, line breaks, and "" for a literal quote.
         */
        public static List<string[]> ReadCsv(string text)
        {
            List<string[]> rows = new List<string[]>();
            List<string> row = new List<string>();
            StringBuilder field = new StringBuilder();
            bool quoted = false;
            int i = 0;
            if (text.Length > 0 && text[0] == (char) 0xFEFF)
            {
                i = 1;   // skip a byte order mark
            }
            for (; i < text.Length; i++)
            {
                char c = text[i];
                if (quoted)
                {
                    if (c == '"' && i + 1 < text.Length && text[i + 1] == '"')
                    {
                        field.Append('"');
                        i++;
                    }
                    else if (c == '"')
                    {
                        quoted = false;
                    }
                    else
                    {
                        field.Append(c);
                    }
                }
                else if (c == '"')
                {
                    quoted = true;
                }
                else if (c == ',')
                {
                    row.Add(field.ToString());
                    field.Clear();
                }
                else if (c == '\n' || c == '\r')
                {
                    if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
                    {
                        i++;
                    }
                    row.Add(field.ToString());
                    field.Clear();
                    rows.Add(row.ToArray());
                    row.Clear();
                }
                else
                {
                    field.Append(c);
                }
            }
            if (field.Length > 0 || row.Count > 0)
            {
                row.Add(field.ToString());
                rows.Add(row.ToArray());
            }
            return rows;
        }
    }
}
