using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ScamFilter
{
    /*
     * Checks a message and gives a verdict. This is the part the app calls.
     *
     * Training (Trainer) happens once, ahead of time, and produces the model file. Using that
     * trained model to judge a new message is called INFERENCE, and it's what this class does.
     * Inference is fast and cheap: build the features, add up weights, apply the sigmoid.
     *
     * ============================================================================
     *  THE PIPELINE (first match wins)
     * ============================================================================
     *   1. BLOCKLIST: the sender, or any link's domain, is a known scam -> UNSAFE.
     *      A hit is strong evidence. A miss means nothing, because scammers switch to fresh
     *      numbers and domains constantly, so most scams aren't on any list yet.
     *   2. WHITELIST: the user trusts this sender -> SAFE.
     *      This runs AFTER the blocklist on purpose. If a friend's account gets hacked and
     *      sends you a known-bad link, the blocklist still catches it. The model still reads
     *      the message too: if it looks like a clear scam, the answer is CAUTION, not SAFE,
     *      because a hacked account sends scams from a sender you trust.
     *   3. MODEL: everything else goes to the model -> p -> SAFE / CAUTION / UNSAFE.
     *
     * The model and lists load the first time they're needed ("lazy loading"); Unload() frees
     * them, and they reload automatically on the next check. A lock keeps two threads (say, the
     * app checking a message while training finishes) from loading at the same time.
     */
    public static class ScamDetector
    {
        // Only one thread at a time may load or use the model and lists (see the class comment).
        private static readonly object Sync = new object();
        private static ScamModel model = null;
        private static HashSet<string> blocklist = null;
        private static HashSet<string> whitelist = null;

        // When each file was last changed, as of loading it. Another ScamFilter window can
        // retrain the model or edit the lists; when a file's date moves, it's loaded again.
        private static DateTime modelStamp = DateTime.MinValue;
        private static DateTime blocklistStamp = DateTime.MinValue;
        private static DateTime whitelistStamp = DateTime.MinValue;

        private static string BlocklistPath
        {
            get { return Paths.ListFile("blocklist.txt"); }
        }

        private static string WhitelistPath
        {
            get { return Paths.ListFile("whitelist.txt"); }
        }

        // Runs the full pipeline on one message.
        public static Verdict Check(MessageRecord r)
        {
            lock (Sync)
            {
                LoadIfNeeded();
                List<LinkInfo> links = MetadataFeatures.DescribeLinks(r);

                // 1. Blocklist
                string hit = BlocklistHit(r, MetadataFeatures.CollectLinks(r));
                if (hit != null)
                {
                    return Verdict.Decided(ScamModel.Unsafe, "blocklist", "On your blocked list: " + hit, links);
                }
                // 2. Whitelist (but a trusted sender can still be a hacked account)
                if (IsWhitelisted(r))
                {
                    double pTrusted = model.Probability(r);
                    if (model.Band(pTrusted) != ScamModel.Unsafe)
                    {
                        return Verdict.Decided(ScamModel.Safe, "whitelist", "Sender is on your trusted list", links);
                    }
                    List<Reason> warning = model.Explain(r, 4, true);
                    warning.Insert(0, new Reason("This is from a sender you trust, but the message itself looks like a scam. "
                        + "Their account may have been hacked.", double.NaN, true));
                    return new Verdict(ScamModel.Caution, pTrusted, "whitelist", warning, links);
                }
                // 3. Model. For SAFE, explain what pushed toward safe; otherwise what pushed toward scam.
                double p = model.Probability(r);
                string band = model.Band(p);
                List<Reason> reasons = model.Explain(r, 4, band != ScamModel.Safe);
                return new Verdict(band, p, "model", reasons, links);
            }
        }

        // Is there a trained model on disk?
        public static bool ModelExists()
        {
            return File.Exists(Paths.ModelFile);
        }

        // The loaded model (loading it if needed), for showing its settings in the app.
        public static ScamModel CurrentModel()
        {
            lock (Sync)
            {
                LoadModelIfNeeded();
                return model;
            }
        }

        // ------------------------------------------------------------------
        // Console helpers (used by the command-line demo)
        // ------------------------------------------------------------------

        public static string CheckText(string sender, string message)
        {
            MessageRecord r = new MessageRecord();
            r.Type = "text";
            r.Sender = sender == null ? "" : sender;
            r.BodyText = message == null ? "" : message;
            return Report(r);
        }

        // Command-line helper: checks an email and prints the verdict.
        public static string CheckEmail(string fromAddress, string displayName, string subject, string body)
        {
            MessageRecord r = new MessageRecord();
            r.Type = "email";
            r.Sender = fromAddress == null ? "" : fromAddress;
            r.DisplayName = displayName == null ? "" : displayName;
            r.Subject = subject == null ? "" : subject;
            r.BodyText = body == null ? "" : body;
            return Report(r);
        }

        // Checks one full record written as JSON (same format as a line of data/records.jsonl).
        public static string CheckJson(string json)
        {
            return Report(MessageRecord.FromJsonText(json));
        }

        // Checks a record, prints its first 80 characters and the verdict, and returns the verdict text.
        private static string Report(MessageRecord r)
        {
            string result = Check(r).ToString();
            Console.WriteLine(r.Preview(80));
            Console.WriteLine("  -> " + result.Replace("\n", "\n  "));
            Console.WriteLine();
            return result;
        }

        // ------------------------------------------------------------------
        // Changing the lists and saving corrections (used by the app's buttons)
        // ------------------------------------------------------------------

        // Adds a sender (phone, email, or domain) to the blocklist or the trusted list.
        public static void AddToList(bool toBlocklist, string entry)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                return;
            }
            DataFiles.AppendLine(toBlocklist ? BlocklistPath : WhitelistPath, entry.Trim());
            ReloadLists();
        }

        // Rereads both list files (after the app edits them).
        public static void ReloadLists()
        {
            lock (Sync)
            {
                blocklist = null;
                whitelist = null;
            }
        }

        /*
         * Saves a message the model got wrong, with the RIGHT label, to data/feedback.jsonl.
         * The trainer reads that file too, so the next training run learns from the correction.
         * These are the most valuable training records you'll get: real messages, from real
         * users, with real metadata.
         */
        public static void SaveCorrection(MessageRecord r, int correctLabel)
        {
            MessageRecord copy = r.Copy();
            copy.Label = correctLabel;
            copy.Source = "user_feedback";
            DataFiles.AppendLine(Paths.FeedbackFile, copy.ToJsonLine());
        }

        // ------------------------------------------------------------------
        // Loading
        // ------------------------------------------------------------------

        private static void LoadIfNeeded()
        {
            LoadModelIfNeeded();
            DateTime stamp = Stamp(BlocklistPath);
            if (blocklist == null || stamp != blocklistStamp)
            {
                blocklist = LoadList(BlocklistPath);
                blocklistStamp = stamp;
            }
            stamp = Stamp(WhitelistPath);
            if (whitelist == null || stamp != whitelistStamp)
            {
                whitelist = LoadList(WhitelistPath);
                whitelistStamp = stamp;
            }
        }

        // Loads the model if it isn't loaded yet, or if the file changed since (another window
        // retrained it).
        private static void LoadModelIfNeeded()
        {
            DateTime stamp = Stamp(Paths.ModelFile);
            if (model == null || stamp != modelStamp)
            {
                ScamModel loaded = null;
                // The file can be mid-swap for a moment while another window saves a new model.
                SharedFiles.Retry(() => loaded = ScamModel.Load(Paths.ModelFile));
                model = loaded;
                modelStamp = stamp;
            }
        }

        // The file's last-changed time (MinValue if it doesn't exist).
        private static DateTime Stamp(string path)
        {
            return File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue;
        }

        // Frees the model, lists, and brand data. They reload automatically on the next check.
        public static void Unload()
        {
            lock (Sync)
            {
                model = null;
                blocklist = null;
                whitelist = null;
                UrlAnalyzer.UnloadBrands();
            }
        }

        // Reads one list file into the set of keys the detector looks up ("phone:...", ...).
        private static HashSet<string> LoadList(string path)
        {
            HashSet<string> set = new HashSet<string>();
            foreach (string entry in DataFiles.ReadList(path))
            {
                set.Add(NormalizeEntry(entry));
            }
            return set;
        }

        /*
         * Every list entry becomes "email:...", "phone:...", or "domain:...", written in one
         * standard form, so a lookup is a single exact HashSet check:
         *   "Alerts@Chase.com"      -> "email:alerts@chase.com"
         *   "+1 (404) 555-0142"     -> "phone:14045550142"
         *   "pay.scam-site.top"     -> "domain:scam-site.top"
         */
        private static string NormalizeEntry(string entry)
        {
            string e = entry.Trim().ToLowerInvariant();
            if (UrlAnalyzer.IsIp(e))
            {
                return "domain:" + e;   // checked first: "194.32.77.10" would otherwise pass for a phone number
            }
            if (e.IndexOf('@') >= 0)
            {
                return "email:" + MetadataFeatures.EmailAddress(e);
            }
            if (Regex.IsMatch(e, @"^[+0-9\s().-]+$"))   // only digits, spaces, and phone punctuation
            {
                return "phone:" + MetadataFeatures.NormalizePhone(e);
            }
            return "domain:" + UrlAnalyzer.RegisteredDomain(UrlAnalyzer.Host(e));
        }

        // ------------------------------------------------------------------
        // List checks
        // ------------------------------------------------------------------

        // Returns the matching entry if anything about the message is blocklisted, else null.
        private static string BlocklistHit(MessageRecord r, List<string> links)
        {
            // Build every key this message could match, in the same standard form as the list.
            List<string> keys = new List<string>();
            string address = MetadataFeatures.EmailAddress(r.Sender);
            if (address.Length > 0)
            {
                keys.Add("email:" + address);
                keys.Add("domain:" + UrlAnalyzer.RegisteredDomain(MetadataFeatures.DomainOf(address)));
            }
            else if (r.Sender.Trim().Length > 0)
            {
                keys.Add("phone:" + MetadataFeatures.NormalizePhone(r.Sender));
            }
            foreach (string link in links)
            {
                keys.Add("domain:" + UrlAnalyzer.RegisteredDomain(UrlAnalyzer.Host(link)));
            }
            foreach (string key in keys)
            {
                if (blocklist.Contains(key))
                {
                    return key.Substring(key.IndexOf(':') + 1);
                }
            }
            return null;
        }

        /*
         * Is the sender trusted? Careful with email: the "From" address can be faked as easily as
         * the return address on an envelope. DMARC (see MetadataFeatures) is the check that it's
         * real, so:
         *   an exact-address entry counts unless the email FAILED DMARC
         *   a whole-domain entry only counts if the email PASSED DMARC
         */
        private static bool IsWhitelisted(MessageRecord r)
        {
            string address = MetadataFeatures.EmailAddress(r.Sender);
            if (address.Length > 0)
            {
                if (r.Dmarc == "fail")
                {
                    return false;
                }
                if (whitelist.Contains("email:" + address))
                {
                    return true;
                }
                string domain = UrlAnalyzer.RegisteredDomain(MetadataFeatures.DomainOf(address));
                return r.Dmarc == "pass" && whitelist.Contains("domain:" + domain);
            }
            if (r.Sender.Trim().Length > 0)
            {
                return whitelist.Contains("phone:" + MetadataFeatures.NormalizePhone(r.Sender));
            }
            return false;
        }
    }
}
