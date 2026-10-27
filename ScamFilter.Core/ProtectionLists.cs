using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ScamFilter
{
    /*
     * Reads and writes the Blocked and Trusted list files (blocklist.txt, whitelist.txt in each
     * account's folder). The format stays the simple one ScamDetector reads, one entry per line,
     * with an optional name after a #:
     *
     *     # comments start with #
     *     14045550142  # Mom
     *     scam-site.top
     *
     * The app writes these files; people edit the lists in the app, where ListRules applies.
     */
    public static class ProtectionLists
    {
        // A line the rules can't read (typed into the file by hand, say). Kept, never silently lost.
        public const string UnreadableMark = "?";

        // Reads a list file. Lines the rules can't understand are kept, marked UnreadableMark.
        public static List<ListEntry> Load(string path)
        {
            List<ListEntry> entries = new List<ListEntry>();
            if (!File.Exists(path))
            {
                return entries;
            }
            foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
            {
                string trimmed = DataFiles.StripBom(line).Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                {
                    continue;
                }
                string value = trimmed;
                string label = "";
                int note = trimmed.IndexOf(" #", StringComparison.Ordinal);
                if (note >= 0)
                {
                    value = trimmed.Substring(0, note).Trim();
                    label = trimmed.Substring(note + 2).Trim();
                }
                ListRules.Result parsed = ListRules.Parse(value);
                ListEntry entry;
                if (parsed.Ok)
                {
                    entry = parsed.Entry;
                }
                else
                {
                    entry = new ListEntry();
                    entry.Kind = EntryKind.Website;
                    entry.Value = value;
                    entry.Display = value;
                    label = label.Length > 0 ? label : UnreadableMark;
                }
                entry.Label = label;
                entries.Add(entry);
            }
            return entries;
        }

        // Writes a list file (safely, see SharedFiles), with a short header saying what the list is.
        public static void Save(string path, List<ListEntry> entries, bool blocked)
        {
            StringBuilder sb = new StringBuilder();
            if (blocked)
            {
                sb.Append("# ScamFilter: your Blocked list. Messages from these senders, or with links to these\n");
                sb.Append("# websites, are marked Unsafe right away. Edit it in ScamFilter (Protections page).\n");
            }
            else
            {
                sb.Append("# ScamFilter: your Trusted list. Messages from these senders are marked Safe unless they\n");
                sb.Append("# look like a scam (their account could be hacked). Edit it in ScamFilter (Protections page).\n");
            }
            sb.Append("# Changes typed straight into this file are noticed and reported as a protection change.\n");
            foreach (ListEntry e in entries)
            {
                sb.Append(e.Value);
                if (e.Label.Length > 0 && e.Label != UnreadableMark)
                {
                    sb.Append("  # ").Append(e.Label);
                }
                sb.Append('\n');
            }
            string folder = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }
            SharedFiles.WriteAtomically(path, sb.ToString());   // (safe with several windows open)
        }
    }
}
