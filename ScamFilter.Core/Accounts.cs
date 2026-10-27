using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ScamFilter
{
    /*
     * Passwords are never stored. What's stored is a HASH: the result of running the password
     * through a one-way function, so the file can check a password without being able to give
     * it back.
     *
     *   stored   = PBKDF2(password, salt, 600,000 rounds)     (32 bytes, saved as hex)
     *   to check:  PBKDF2(what was typed, same salt, same rounds) == stored ?
     *
     * Why each piece:
     *   SALT     16 random bytes made fresh for every password and saved next to the hash. Two
     *            people with the same password get different hashes, and a precomputed table of
     *            common passwords' hashes is useless.
     *   ROUNDS   PBKDF2 repeats its hash function 600,000 times (the 2023 OWASP recommendation
     *            for PBKDF2-HMAC-SHA256). Checking ONE password takes a fraction of a second,
     *            which nobody notices; trying millions of guesses takes days.
     *   COMPARE  CryptographicOperations.FixedTimeEquals takes the same time whether the first
     *            byte or the last one differs, so timing can't leak how close a guess was.
     *
     * PBKDF2 is built into .NET; it's not an AI library, it's the standard way to store passwords.
     */
    public static class PasswordHasher
    {
        // How many times PBKDF2 repeats its hash (see the class comment), and the sizes in bytes
        // of the random salt and of the finished hash.
        public const int Rounds = 600000;
        private const int SaltBytes = 16;
        private const int HashBytes = 32;

        // Returns (salt, hash) as hex strings.
        public static string[] Hash(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, Rounds, HashAlgorithmName.SHA256, HashBytes);
            return new string[] { Convert.ToHexString(salt), Convert.ToHexString(hash) };
        }

        // True if `password` gives the same hash as the stored one. `rounds` is the count the
        // stored hash was made with, so an old hash still checks even if Rounds goes up later.
        public static bool Verify(string password, string saltHex, string hashHex, int rounds)
        {
            if (string.IsNullOrEmpty(saltHex) || string.IsNullOrEmpty(hashHex) || password == null)
            {
                return false;
            }
            byte[] salt;
            byte[] expected;
            try
            {
                salt = Convert.FromHexString(saltHex);
                expected = Convert.FromHexString(hashHex);
            }
            catch (FormatException)
            {
                return false;
            }
            byte[] actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, rounds, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }

        /*
         * The password rules (hard-coded, like the list rules). Returns why a password is refused,
         * or null if it's fine. Length matters far more than symbols, so the main rule is length.
         */
        public static string WhyNotAllowed(string password, string accountName)
        {
            if (password == null || password.Length < 8)
            {
                return "Use at least 8 characters. A short phrase is easier to remember and harder to guess.";
            }
            if (password.Length > 128)
            {
                return "That's longer than 128 characters.";
            }
            bool allSame = true;
            foreach (char c in password)
            {
                if (c != password[0])
                {
                    allSame = false;
                }
            }
            if (allSame)
            {
                return "That's one character repeated. Pick something harder to guess.";
            }
            string lower = password.ToLowerInvariant();
            if (accountName != null && accountName.Trim().Length > 0 && lower.Contains(accountName.Trim().ToLowerInvariant()))
            {
                return "Don't put your name in your password.";
            }
            foreach (string common in CommonPasswords)
            {
                if (lower == common)
                {
                    return "That's one of the most common passwords, so it's the first thing anyone would try.";
                }
            }
            return null;
        }

        // Passwords so common that people try them first (lowercase).
        private static readonly string[] CommonPasswords = {
            "password", "password1", "password123", "12345678", "123456789", "1234567890", "qwerty123",
            "qwertyuiop", "iloveyou", "11111111", "abc12345", "abcd1234", "letmein1", "welcome1",
            "sunshine", "princess", "football", "baseball", "superman", "trustno1", "scamfilter"
        };

        // A recovery code: 16 letters and digits that are hard to mix up (no 0/O, 1/I/L),
        // shown as XXXX-XXXX-XXXX-XXXX. 31^16 (about 7 x 10^23) possibilities, so it can't be guessed.
        private const string CodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

        // Makes a new random recovery code, like "7KQM-2HXP-9WTC-4BNR".
        public static string NewRecoveryCode()
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++)
            {
                if (i > 0 && i % 4 == 0)
                {
                    sb.Append('-');
                }
                sb.Append(CodeAlphabet[RandomNumberGenerator.GetInt32(CodeAlphabet.Length)]);
            }
            return sb.ToString();
        }

        // "abcd efgh-ijkl mnop" -> "ABCDEFGHIJKLMNOP": how a typed recovery code is compared.
        public static string CleanRecoveryCode(string typed)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in (typed ?? "").ToUpperInvariant())
            {
                if (char.IsLetterOrDigit(c))
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }
    }

    /*
     * One person's ScamFilter account on this PC. Each account has its own folder
     * (accounts\<Id>\) for its Blocked and Trusted lists, Outlook sign-in, and alert settings.
     *
     * An account can be unlocked with its password, its linked Microsoft account, or both:
     *   PasswordHash empty      -> Microsoft only
     *   MicrosoftUser empty     -> password only
     */
    public class Account
    {
        public string Id = "";                          // random ID, also the name of the account's folder
        public string Name = "";                        // what the person called it ("Jordan", "Grandma")
        public string PasswordSalt = "";                // random salt for the password hash (hex); empty = no password
        public string PasswordHash = "";                // PBKDF2 hash of the password (hex); empty = no password
        public string RecoverySalt = "";                // the same two things for the recovery code
        public string RecoveryHash = "";                // (see RecoverySalt)
        public int Rounds = PasswordHasher.Rounds;      // PBKDF2 rounds used for both hashes above
        public string MicrosoftUser = "";               // the Microsoft account's email address
        public string MicrosoftHomeId = "";             // MSAL's permanent ID for that account
        public DateTime CreatedUtc = DateTime.UtcNow;   // when the account was made

        // Wrong-password tracking (see AccountStore.CheckPassword)
        public int FailedAttempts = 0;                        // how many wrong passwords in a row
        public DateTime LockedUntilUtc = DateTime.MinValue;   // locked until this time after too many wrong passwords

        // A fingerprint of the protection files as ScamFilter last saved them. If the files
        // change without ScamFilter (typed into by hand), the fingerprints won't match.
        public string ProtectionFingerprint = "";

        // What accounts.json said about this account when this window last read or wrote it
        // (null for an account this window just made). AccountStore.Save compares against it to
        // tell "this window changed it" from "another window changed it". See AccountStore.
        internal Dictionary<string, string> Saved = null;

        // Can it be unlocked with a password?
        public bool HasPassword
        {
            get { return PasswordHash.Length > 0; }
        }

        // Is a Microsoft account linked (so it can be unlocked by signing in to Microsoft)?
        public bool HasMicrosoft
        {
            get { return MicrosoftHomeId.Length > 0; }
        }

        // How it can be unlocked, for the account list: "Password and Microsoft (x@outlook.com)"
        public string SignInDescription
        {
            get
            {
                if (HasPassword && HasMicrosoft)
                {
                    return "Password or Microsoft (" + MicrosoftUser + ")";
                }
                return HasMicrosoft ? "Microsoft (" + MicrosoftUser + ")" : "Password";
            }
        }
    }

    /*
     * All accounts, saved in %LOCALAPPDATA%\ScamFilter\accounts.json.
     *
     * HONEST LIMITS: this protects against changes made THROUGH ScamFilter (including someone
     * being talked into it over the phone). It isn't a vault: anyone who can sign in to the
     * Windows account can open the files in Notepad. That's why ScamFilter also fingerprints the
     * protection files and reports changes it didn't make (ProtectionFingerprint).
     *
     * SEVERAL WINDOWS AT ONCE
     * Two copies of ScamFilter can be open at the same time, and both may save accounts.json.
     * If each simply wrote out its own copy, the second save would undo the first (say, a
     * password changed in one window, or a wrong-password count in the other). So Save merges,
     * one field at a time, while holding accounts.lock (see FileLock):
     *
     *     changed in THIS window since it last read the file?  -> this window's value
     *     otherwise                                             -> what the file says now
     *
     * Accounts another window added are kept (and appear in this window's list too), and an
     * account this window removed stays removed. Refresh pulls one account's latest values from
     * the file; the unlock dialog uses it before checking a password, so wrong guesses add up
     * across windows and can't dodge the lockout by switching windows.
     */
    public static class AccountStore
    {
        // Wrong passwords in a row before the account locks for a while (see Failed).
        public const int AttemptsBeforeLockout = 5;

        // %LOCALAPPDATA%\ScamFilter\accounts.json: every account on this PC.
        public static string FilePath
        {
            get { return Path.Combine(Paths.BaseDir, "accounts.json"); }
        }

        // accounts\<id>\: the account's own lists, Outlook sign-in, and alert settings.
        public static string FolderOf(Account a)
        {
            return Path.Combine(Paths.BaseDir, "accounts", a.Id);
        }

        // Held while accounts.json is being read or written (see FileLock in SharedFiles.cs).
        public static string LockPath
        {
            get { return Path.Combine(Paths.BaseDir, "accounts.lock"); }
        }

        // Every account on this PC, as loaded from accounts.json.
        public class Store
        {
            public List<Account> Accounts = new List<Account>();   // in the order they were made
            public string LastUsedId = "";                         // the account opened last time (opens straight away next time)

            // For merging with other windows' saves (see the class comment): the accounts and
            // the last-used ID as this window last read or wrote them.
            internal HashSet<string> KnownIds = new HashSet<string>();
            internal string SavedLastUsedId = "";

            // The account with this ID, or null.
            public Account Find(string id)
            {
                foreach (Account a in Accounts)
                {
                    if (a.Id == id)
                    {
                        return a;
                    }
                }
                return null;
            }
        }

        // ------------------------------------------------------------------
        // Creating accounts
        // ------------------------------------------------------------------

        // Why a name is refused, or null.
        public static string WhyNameNotAllowed(Store store, string name, Account except)
        {
            string n = (name ?? "").Trim();
            if (n.Length == 0)
            {
                return "Type a name, like Jordan or Grandma.";
            }
            if (n.Length > 40)
            {
                return "Keep the name to 40 characters or fewer.";
            }
            foreach (char c in n)
            {
                if (char.IsControl(c))
                {
                    return "Names can't contain line breaks.";
                }
            }
            foreach (Account a in store.Accounts)
            {
                if (a != except && a.Name.Equals(n, StringComparison.OrdinalIgnoreCase))
                {
                    return "There's already an account called " + a.Name + ".";
                }
            }
            return null;
        }

        // A new account. Returns its recovery code when it has a password (shown to the user ONCE).
        public static Account Create(Store store, string name, string password, out string recoveryCode)
        {
            Account a = new Account();
            a.Id = Guid.NewGuid().ToString("N");
            a.Name = name.Trim();
            recoveryCode = "";
            if (!string.IsNullOrEmpty(password))
            {
                SetPassword(a, password);
                recoveryCode = NewRecoveryCode(a);
            }
            store.Accounts.Add(a);
            return a;
        }

        // Sets a new password (stored as a salted hash) and clears the wrong-password count.
        public static void SetPassword(Account a, string password)
        {
            string[] hashed = PasswordHasher.Hash(password);
            a.PasswordSalt = hashed[0];
            a.PasswordHash = hashed[1];
            a.Rounds = PasswordHasher.Rounds;
            a.FailedAttempts = 0;
            a.LockedUntilUtc = DateTime.MinValue;
        }

        // Makes a new recovery code and stores its hash. Returns the code itself, which is
        // shown to the person once and never stored.
        public static string NewRecoveryCode(Account a)
        {
            string code = PasswordHasher.NewRecoveryCode();
            string[] hashed = PasswordHasher.Hash(PasswordHasher.CleanRecoveryCode(code));
            a.RecoverySalt = hashed[0];
            a.RecoveryHash = hashed[1];
            return code;
        }

        // ------------------------------------------------------------------
        // Checking passwords
        // ------------------------------------------------------------------

        public enum CheckResult { Correct, Wrong, LockedOut, JustLockedOut }

        /*
         * Checks a password, counting wrong tries:
         *   5 wrong in a row          -> locked for 5 minutes (JustLockedOut: time to send an alert)
         *   each wrong try after that -> the lock doubles, up to an hour
         *   a right password          -> the count starts over
         * While locked, nothing is checked at all, so guessing gets nowhere.
         */
        public static CheckResult CheckPassword(Account a, string password, DateTime nowUtc)
        {
            if (nowUtc < a.LockedUntilUtc)
            {
                return CheckResult.LockedOut;
            }
            if (PasswordHasher.Verify(password, a.PasswordSalt, a.PasswordHash, a.Rounds))
            {
                a.FailedAttempts = 0;
                a.LockedUntilUtc = DateTime.MinValue;
                return CheckResult.Correct;
            }
            return Failed(a, nowUtc);
        }

        // Like CheckPassword, for the recovery code. Wrong codes count as wrong passwords.
        public static CheckResult CheckRecoveryCode(Account a, string code, DateTime nowUtc)
        {
            if (nowUtc < a.LockedUntilUtc)
            {
                return CheckResult.LockedOut;
            }
            if (PasswordHasher.Verify(PasswordHasher.CleanRecoveryCode(code), a.RecoverySalt, a.RecoveryHash, a.Rounds))
            {
                a.FailedAttempts = 0;
                a.LockedUntilUtc = DateTime.MinValue;
                return CheckResult.Correct;
            }
            return Failed(a, nowUtc);
        }

        // One more wrong try: counts it, and locks the account once there have been too many.
        private static CheckResult Failed(Account a, DateTime nowUtc)
        {
            a.FailedAttempts++;
            if (a.FailedAttempts < AttemptsBeforeLockout)
            {
                return CheckResult.Wrong;
            }
            int extra = Math.Min(a.FailedAttempts - AttemptsBeforeLockout, 4);   // 5, 10, 20, 40, then 60 minutes
            double minutes = Math.Min(5 * Math.Pow(2, extra), 60);
            a.LockedUntilUtc = nowUtc.AddMinutes(minutes);
            return a.FailedAttempts == AttemptsBeforeLockout ? CheckResult.JustLockedOut : CheckResult.LockedOut;
        }

        // How many tries are left before the account locks.
        public static int AttemptsLeft(Account a)
        {
            return Math.Max(0, AttemptsBeforeLockout - a.FailedAttempts);
        }

        // ------------------------------------------------------------------
        // Loading and saving
        // ------------------------------------------------------------------

        public static Store Load()
        {
            FileLock held = FileLock.Acquire(LockPath, TimeSpan.FromSeconds(10));
            try
            {
                Store store = ReadFile();
                foreach (Account a in store.Accounts)
                {
                    a.Saved = Fields(a);
                    store.KnownIds.Add(a.Id);
                }
                store.SavedLastUsedId = store.LastUsedId;
                return store;
            }
            finally
            {
                if (held != null)
                {
                    held.Release();
                }
            }
        }

        // accounts.json as it is on disk right now (an empty store if there's no file yet).
        private static Store ReadFile()
        {
            Store store = new Store();
            if (!File.Exists(FilePath))
            {
                return store;
            }
            JsonDocument doc = JsonDocument.Parse(File.ReadAllText(FilePath, Encoding.UTF8));
            try
            {
                JsonElement root = doc.RootElement;
                store.LastUsedId = Str(root, "lastUsed");
                JsonElement list;
                if (root.TryGetProperty("accounts", out list) && list.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement e in list.EnumerateArray())
                    {
                        Account a = new Account();
                        a.Id = Str(e, "id");
                        a.Name = Str(e, "name");
                        a.PasswordSalt = Str(e, "passwordSalt");
                        a.PasswordHash = Str(e, "passwordHash");
                        a.RecoverySalt = Str(e, "recoverySalt");
                        a.RecoveryHash = Str(e, "recoveryHash");
                        a.MicrosoftUser = Str(e, "microsoftUser");
                        a.MicrosoftHomeId = Str(e, "microsoftHomeId");
                        a.ProtectionFingerprint = Str(e, "protectionFingerprint");
                        JsonElement value;
                        if (e.TryGetProperty("rounds", out value) && value.ValueKind == JsonValueKind.Number)
                        {
                            a.Rounds = value.GetInt32();
                        }
                        if (e.TryGetProperty("failedAttempts", out value) && value.ValueKind == JsonValueKind.Number)
                        {
                            a.FailedAttempts = value.GetInt32();
                        }
                        DateTime when;
                        if (DateTime.TryParse(Str(e, "lockedUntilUtc"), System.Globalization.CultureInfo.InvariantCulture,
                                              System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out when))
                        {
                            a.LockedUntilUtc = when;
                        }
                        if (DateTime.TryParse(Str(e, "createdUtc"), System.Globalization.CultureInfo.InvariantCulture,
                                              System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out when))
                        {
                            a.CreatedUtc = when;
                        }
                        if (a.Id.Length > 0)
                        {
                            store.Accounts.Add(a);
                        }
                    }
                }
            }
            finally
            {
                doc.Dispose();
            }
            return store;
        }

        /*
         * Saves the store, merged with whatever other windows saved meanwhile (see the class
         * comment). Afterwards `store` also shows the other windows' changes.
         */
        public static void Save(Store store)
        {
            Directory.CreateDirectory(Paths.BaseDir);
            FileLock held = FileLock.Acquire(LockPath, TimeSpan.FromSeconds(10));
            if (held == null)
            {
                throw new IOException("Another ScamFilter window is busy saving accounts. Try again in a moment.");
            }
            try
            {
                Merge(store, ReadFile());
                WriteFile(store);
                foreach (Account a in store.Accounts)
                {
                    a.Saved = Fields(a);
                }
                store.KnownIds = new HashSet<string>();
                foreach (Account a in store.Accounts)
                {
                    store.KnownIds.Add(a.Id);
                }
                store.SavedLastUsedId = store.LastUsedId;
            }
            finally
            {
                held.Release();
            }
        }

        /*
         * Brings one account up to date with accounts.json (fields this window changed and
         * hasn't saved yet are kept). Used before checking a password.
         */
        public static void Refresh(Store store, Account a)
        {
            FileLock held = FileLock.Acquire(LockPath, TimeSpan.FromSeconds(10));
            if (held == null)
            {
                return;   // can't read it right now; the values this window has are used
            }
            try
            {
                Account onDisk = ReadFile().Find(a.Id);
                if (onDisk != null)
                {
                    Dictionary<string, string> latest = Fields(onDisk);
                    Apply(a, MergeFields(Fields(a), a.Saved, latest));
                    a.Saved = latest;
                }
            }
            finally
            {
                held.Release();
            }
        }

        // Puts this window's changes on top of what's on disk (see the class comment).
        private static void Merge(Store mine, Store disk)
        {
            List<Account> result = new List<Account>();
            foreach (Account d in disk.Accounts)
            {
                Account m = mine.Find(d.Id);
                if (m == null)
                {
                    if (mine.KnownIds.Contains(d.Id))
                    {
                        continue;   // this window removed it
                    }
                    d.Saved = Fields(d);
                    result.Add(d);   // another window added it
                    continue;
                }
                Apply(m, MergeFields(Fields(m), m.Saved, Fields(d)));
                result.Add(m);
            }
            foreach (Account m in mine.Accounts)
            {
                // New in this window: added. (One this window knew that's gone from the file was
                // removed by another window, so it stays removed.)
                if (disk.Find(m.Id) == null && !mine.KnownIds.Contains(m.Id))
                {
                    result.Add(m);
                }
            }
            mine.Accounts = result;
            if (mine.LastUsedId == mine.SavedLastUsedId)
            {
                mine.LastUsedId = disk.LastUsedId;
            }
        }

        // Field by field: this window's value if it changed it, otherwise the file's.
        private static Dictionary<string, string> MergeFields(Dictionary<string, string> mine,
            Dictionary<string, string> savedByMe, Dictionary<string, string> disk)
        {
            Dictionary<string, string> merged = new Dictionary<string, string>();
            foreach (KeyValuePair<string, string> e in mine)
            {
                string before;
                bool changedHere = savedByMe == null || !savedByMe.TryGetValue(e.Key, out before) || before != e.Value;
                string onDisk;
                merged[e.Key] = changedHere || !disk.TryGetValue(e.Key, out onDisk) ? e.Value : onDisk;
            }
            return merged;
        }

        // An account's saved fields as text, for comparing and merging.
        private static Dictionary<string, string> Fields(Account a)
        {
            System.Globalization.CultureInfo inv = System.Globalization.CultureInfo.InvariantCulture;
            Dictionary<string, string> f = new Dictionary<string, string>();
            f["name"] = a.Name;
            f["passwordSalt"] = a.PasswordSalt;
            f["passwordHash"] = a.PasswordHash;
            f["recoverySalt"] = a.RecoverySalt;
            f["recoveryHash"] = a.RecoveryHash;
            f["rounds"] = a.Rounds.ToString(inv);
            f["microsoftUser"] = a.MicrosoftUser;
            f["microsoftHomeId"] = a.MicrosoftHomeId;
            // (SpecifyKind: the same moment always gives the same text, however it was made)
            f["createdUtc"] = DateTime.SpecifyKind(a.CreatedUtc, DateTimeKind.Utc).ToString("o", inv);
            f["failedAttempts"] = a.FailedAttempts.ToString(inv);
            f["lockedUntilUtc"] = DateTime.SpecifyKind(a.LockedUntilUtc, DateTimeKind.Utc).ToString("o", inv);
            f["protectionFingerprint"] = a.ProtectionFingerprint;
            return f;
        }

        // The other direction from Fields: puts the text values back into the account.
        private static void Apply(Account a, Dictionary<string, string> f)
        {
            System.Globalization.CultureInfo inv = System.Globalization.CultureInfo.InvariantCulture;
            System.Globalization.DateTimeStyles utc = System.Globalization.DateTimeStyles.AdjustToUniversal
                | System.Globalization.DateTimeStyles.AssumeUniversal;
            a.Name = f["name"];
            a.PasswordSalt = f["passwordSalt"];
            a.PasswordHash = f["passwordHash"];
            a.RecoverySalt = f["recoverySalt"];
            a.RecoveryHash = f["recoveryHash"];
            a.Rounds = int.Parse(f["rounds"], inv);
            a.MicrosoftUser = f["microsoftUser"];
            a.MicrosoftHomeId = f["microsoftHomeId"];
            a.CreatedUtc = DateTime.Parse(f["createdUtc"], inv, utc);
            a.FailedAttempts = int.Parse(f["failedAttempts"], inv);
            a.LockedUntilUtc = DateTime.Parse(f["lockedUntilUtc"], inv, utc);
            a.ProtectionFingerprint = f["protectionFingerprint"];
        }

        // Writes accounts.json (called while holding the lock).
        private static void WriteFile(Store store)
        {
            MemoryStream buffer = new MemoryStream();
            Utf8JsonWriter w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true });
            w.WriteStartObject();
            w.WriteString("lastUsed", store.LastUsedId);
            w.WriteStartArray("accounts");
            foreach (Account a in store.Accounts)
            {
                w.WriteStartObject();
                w.WriteString("id", a.Id);
                w.WriteString("name", a.Name);
                w.WriteString("passwordSalt", a.PasswordSalt);
                w.WriteString("passwordHash", a.PasswordHash);
                w.WriteString("recoverySalt", a.RecoverySalt);
                w.WriteString("recoveryHash", a.RecoveryHash);
                w.WriteNumber("rounds", a.Rounds);
                w.WriteString("microsoftUser", a.MicrosoftUser);
                w.WriteString("microsoftHomeId", a.MicrosoftHomeId);
                w.WriteString("createdUtc", a.CreatedUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
                w.WriteNumber("failedAttempts", a.FailedAttempts);
                w.WriteString("lockedUntilUtc", a.LockedUntilUtc.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
                w.WriteString("protectionFingerprint", a.ProtectionFingerprint);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
            w.Flush();
            w.Dispose();
            SharedFiles.WriteAtomically(FilePath, buffer.ToArray());
            buffer.Close();
        }

        // A string property of a JSON object, or "" if it's missing.
        private static string Str(JsonElement e, string name)
        {
            JsonElement value;
            if (e.TryGetProperty(name, out value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }
            return "";
        }
    }

    /*
     * A "fingerprint" of an account's protection files: a SHA-256 hash of each one. ScamFilter
     * saves the fingerprint every time IT changes a file. If a file changes some other way
     * (opened in Notepad and edited), the next start finds a different hash and reports it as
     * a protection change. It's a tripwire, not a lock: it notices, it doesn't prevent.
     */
    public static class ProtectionFingerprint
    {
        // Each file, and what to call it in an alert.
        private static readonly string[] Names = { "blocklist.txt", "whitelist.txt", "alerts.json", "outlook.json" };
        private static readonly string[] Descriptions = { "the Blocked list", "the Trusted list", "the alert settings",
                                                          "the automatic Outlook check setting" };

        // "blocklist.txt=3F2A...;whitelist.txt=none;..."
        public static string Compute(string accountFolder)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string name in Names)
            {
                string path = Path.Combine(accountFolder, name);
                string hash = File.Exists(path) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).Substring(0, 32) : "none";
                sb.Append(name).Append('=').Append(hash).Append(';');
            }
            return sb.ToString();
        }

        // Which files differ between two fingerprints, described for people. Empty if none.
        public static List<string> Differences(string before, string after)
        {
            List<string> changed = new List<string>();
            if (string.IsNullOrEmpty(before))
            {
                return changed;   // nothing recorded yet: nothing to compare with
            }
            for (int i = 0; i < Names.Length; i++)
            {
                if (Part(before, Names[i]) != Part(after, Names[i]))
                {
                    changed.Add(Descriptions[i] + " was edited outside ScamFilter");
                }
            }
            return changed;
        }

        // The hash part for one file out of a fingerprint like "blocklist.txt=AB12...;whitelist.txt=...;".
        private static string Part(string fingerprint, string name)
        {
            foreach (string piece in fingerprint.Split(';'))
            {
                if (piece.StartsWith(name + "=", StringComparison.Ordinal))
                {
                    return piece.Substring(name.Length + 1);
                }
            }
            return "";
        }
    }
}
