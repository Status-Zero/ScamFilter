using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace ScamFilter
{
    /*
     * Where everything lives on disk:
     *
     *   <BaseDir>/data/records.jsonl          training data (one JSON record per line)
     *   <BaseDir>/data/feedback.jsonl         corrections saved from the app's "Mark as..." buttons
     *   <BaseDir>/data/brands.txt             brands and their official domains
     *   <BaseDir>/data/blocklist.txt          blocked senders for the console trainer (the app keeps
     *   <BaseDir>/data/whitelist.txt          trusted senders      its lists per account, see below)
     *   <BaseDir>/model/scam_model.txt        the trained model
     *   <BaseDir>/model/training_report.txt   the report from the last training run
     *   <BaseDir>/accounts.json               the accounts on this PC (see AccountStore)
     *   <BaseDir>/accounts/<id>/              one account's lists, Outlook sign-in, and alerts
     *
     * The console trainer uses the folder you run it from. The desktop app uses
     * %LOCALAPPDATA%\ScamFilter, so it works no matter where the .exe is kept.
     */
    public static class Paths
    {
        // The folder that holds data\ and model\. The app sets it at start-up (see the class comment).
        public static string BaseDir = Directory.GetCurrentDirectory();

        /*
         * The signed-in account's own folder (accounts\<id>), set by the app. Its Blocked and
         * Trusted lists live there. When it's null (the console trainer), the lists in data\
         * are used instead.
         */
        public static string AccountFolder = null;

        // blocklist.txt or whitelist.txt for whoever is using ScamFilter (see AccountFolder).
        public static string ListFile(string name)
        {
            return AccountFolder != null ? Path.Combine(AccountFolder, name) : DataFile(name);
        }

        // <BaseDir>\data
        public static string DataFolder
        {
            get { return Path.Combine(BaseDir, "data"); }
        }

        // A file in the data folder.
        public static string DataFile(string name)
        {
            return Path.Combine(DataFolder, name);
        }

        // The training data (see data\SOURCES.md).
        public static string RecordsFile
        {
            get { return DataFile("records.jsonl"); }
        }

        // Results the user marked with "This is a scam" / "This is safe".
        public static string FeedbackFile
        {
            get { return DataFile("feedback.jsonl"); }
        }

        // The trained model.
        public static string ModelFile
        {
            get { return Path.Combine(BaseDir, "model", "scam_model.txt"); }
        }

        // The report from the last training run.
        public static string ReportFile
        {
            get { return Path.Combine(BaseDir, "model", "training_report.txt"); }
        }

        // The default data files built into the program (as "embedded resources").
        private static readonly string[] DefaultFiles = { "brands.txt", "blocklist.txt", "whitelist.txt", "records.jsonl" };

        /*
         * SHA-256 fingerprints of the default files that EARLIER versions shipped.
         * If a file on disk still matches one of these exactly, nobody has edited it, so it's
         * safe to replace with the newer default. A file you edited never matches, so it's
         * left alone. (Add the old fingerprint here whenever a default file changes.)
         */
        private static readonly Dictionary<string, string[]> PreviousDefaults = new Dictionary<string, string[]>
        {
            // version 1.0, then 1.1
            { "brands.txt", new string[] { "762679F8A390693412D9A2FE79D924572214355C4B20A7196D9F672F5EA37E3D",
                                           "73B2ADCAF06FC9B98B9150C5C284049F240498B52EECEAB2D39E02A558188834" } },
            { "blocklist.txt", new string[] { "4A6ACB34F77D01CE9C8A0659F11C0EEED282F94D6CED26A3CD0BE6A7BC19BC5C",
                                              "8D08EB9F6D819C31351A21F64D11E354027039A285509C190FC782B8BF0BDD3D" } },
            { "whitelist.txt", new string[] { "5F8D9335BA282ED138D8873C526C7FE756FBC7DDAD647032158D06266AE05D05",
                                              "76A6B6D9F12F3DB64F2079AB907DEE2A35A375F5BB0BC75F71B938CCBC77569C" } },
            // versions 1.0 and 1.1 shipped the same 69 example messages; then version 1.3's
            // 13,400 public-dataset records; then the 19,152 records of versions 1.4 to 1.5.3
            // (1.5.4 replaced the names and places in the example messages with made-up ones)
            { "records.jsonl", new string[] { "C657D61F240F67C858C37D845886A40683B99E0D0EB13CD835BC63789EC56D46",
                                              "10148638315CA9E4184D3D0B8ED8E21397C0274E9D2102D267A6761B695C0A4D",
                                              "F2AB67CC5999573B58406D8465A21877683C799F20859F585D33392C6E1D860A" } }
        };

        /*
         * Writes out any default data file that's missing, and upgrades default files you
         * haven't edited (see PreviousDefaults). Files you've changed are never touched.
         *
         * Then the built-in, already-trained model. It's copied in when:
         *   - there's no model yet, or the model is from an older version (it reads text
         *     differently, so it can't be used as-is), or
         *   - the training data was just upgraded and you haven't saved any corrections, so the
         *     built-in model was trained on exactly the data you now have.
         * If you HAVE saved corrections, a current model of your own is kept; press "Train now"
         * to fold the new data in.
         */
        public static void EnsureDefaultData()
        {
            Directory.CreateDirectory(DataFolder);
            // Two ScamFilter windows starting at once would both write these files: one at a time.
            FileLock held = FileLock.Acquire(DataFile("setup.lock"), TimeSpan.FromSeconds(30));
            try
            {
                WriteDefaults();
            }
            finally
            {
                if (held != null)
                {
                    held.Release();
                }
            }
        }

        // The work of EnsureDefaultData, done while holding setup.lock.
        private static void WriteDefaults()
        {
            Assembly assembly = typeof(Paths).Assembly;
            bool recordsReplaced = false;
            foreach (string name in DefaultFiles)
            {
                byte[] current = ReadResource(assembly, name);
                if (current == null)
                {
                    continue;
                }
                string target = DataFile(name);
                if (!File.Exists(target))
                {
                    SharedFiles.WriteAtomically(target, current);
                    recordsReplaced |= name == "records.jsonl";
                    continue;
                }
                string onDisk = Fingerprint(File.ReadAllBytes(target));
                if (onDisk != Fingerprint(current) && Array.IndexOf(PreviousDefaults[name], onDisk) >= 0)
                {
                    SharedFiles.WriteAtomically(target, current);   // an unedited old default: upgrade it
                    recordsReplaced |= name == "records.jsonl";
                }
            }

            bool noCorrections = !File.Exists(FeedbackFile) || new FileInfo(FeedbackFile).Length == 0;
            if (!ScamModel.HasCurrentFormat(ModelFile) || (recordsReplaced && noCorrections))
            {
                byte[] model = ReadResource(assembly, "scam_model.txt");
                byte[] report = ReadResource(assembly, "training_report.txt");
                if (model != null)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(ModelFile));
                    SharedFiles.WriteAtomically(ModelFile, model);
                    if (report != null)
                    {
                        SharedFiles.WriteAtomically(ReportFile, report);
                    }
                }
            }
        }

        // One of the files built into the program, or null if it isn't there.
        private static byte[] ReadResource(Assembly assembly, string name)
        {
            Stream resource = assembly.GetManifestResourceStream("ScamFilter.Defaults." + name);
            if (resource == null)
            {
                return null;
            }
            MemoryStream bytes = new MemoryStream();
            resource.CopyTo(bytes);
            resource.Close();
            return bytes.ToArray();
        }

        // A file's SHA-256 "fingerprint": any change to the file, even one character, changes it completely.
        private static string Fingerprint(byte[] bytes)
        {
            return Convert.ToHexString(SHA256.HashData(bytes));
        }
    }
}
