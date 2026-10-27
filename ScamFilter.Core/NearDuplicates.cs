using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace ScamFilter
{
    /*
     * Finds groups of NEAR-DUPLICATE messages: the same scam campaign sent with a different name
     * or tracking number, the same newsletter template every week, a reply that quotes the email
     * before it.
     *
     * ============================================================================
     *  WHY THIS MATTERS FOR TESTING
     * ============================================================================
     * The test set is supposed to be messages the model has never seen. If one copy of a
     * campaign lands in training and another copy in the test set, the "test" question is one
     * the model already studied, and the score looks better than the model really is. In this
     * project's data about 1 message in 6 has a near-copy somewhere else (two thirds of the
     * mailing-list emails, because replies quote each other).
     *
     * So Trainer splits by GROUP: every message in a group goes to the same side (all
     * training, or all test). Exact duplicates are already removed when data is imported; this
     * catches the ones that differ by a few words.
     *
     * ============================================================================
     *  HOW SIMILARITY IS MEASURED
     * ============================================================================
     * Each message becomes a SET of "shingles": every run of 3 words in a row.
     *     "your account has been locked"  ->  {"your account has", "account has been", "has been locked"}
     * Digits become 0 first, so "order 4471" and "order 9902" look the same.
     *
     * Two messages are near-duplicates when their shingle sets overlap a lot. The overlap is
     * measured with the JACCARD SIMILARITY:
     *
     *     J(A, B) = |A and B| / |A or B|      (shared shingles / all shingles)
     *
     * 1.0 means identical, 0.0 means nothing in common. At least Threshold (0.5) counts as a
     * near-duplicate.
     *
     * ============================================================================
     *  MAKING IT FAST: MINHASH
     * ============================================================================
     * Comparing every message with every other message is n * n comparisons: 20,000 messages
     * would be 200 million set comparisons. MinHash finds the likely pairs without that.
     *
     * The trick: give every possible shingle a random number (a hash), and for each message
     * keep only the SMALLEST number among its shingles. For two messages A and B:
     *
     *     chance that A and B have the same smallest number  =  J(A, B)
     *
     * (Imagine shuffling all the shingles of A and B together; the one that comes first is
     * equally likely to be any of them, and both messages share that "first" exactly when it's
     * one of their shared shingles.)
     *
     * Do that with 64 different random numberings and you get a SIGNATURE of 64 numbers per
     * message. Similar messages agree in many positions.
     *
     * Then LSH ("locality-sensitive hashing"): cut the signature into 16 bands of 4 numbers.
     * Messages whose band 1 is identical go in the same bucket, and the same for band 2, and so
     * on. Only messages that share a bucket are compared for real (exact Jaccard). Two messages
     * with J = 0.5 share at least one bucket about 64% of the time; with J = 0.8, 99.9% of the
     * time; with J = 0.2, under 3%. Pairs just above the threshold are occasionally missed,
     * which is fine: this is a safety measure, not a guarantee.
     *
     * Groups are built with UNION-FIND: start with every message in its own group, and merge
     * the groups of every near-duplicate pair. If A ~ B and B ~ C, then A, B, and C end up in one
     * group even if A and C aren't directly similar.
     */
    public static class NearDuplicates
    {
        public const double Threshold = 0.5;   // Jaccard similarity that counts as a near-duplicate
        private const int HashCount = 64;      // numbers per signature
        private const int RowsPerBand = 4;     // 64 / 4 = 16 bands
        private const int MaxChars = 3000;     // the model reads about this much, so compare this much

        // Returns a group number for each record. Records with the same number are near-duplicates.
        public static int[] Groups(List<MessageRecord> records)
        {
            int n = records.Count;
            List<HashSet<ulong>> shingles = new List<HashSet<ulong>>(n);
            ulong[][] signatures = new ulong[n][];
            ulong[] seeds = MakeSeeds();
            for (int i = 0; i < n; i++)
            {
                HashSet<ulong> set = Shingles(records[i]);
                shingles.Add(set);
                signatures[i] = Signature(set, seeds);
            }

            int[] parent = new int[n];
            for (int i = 0; i < n; i++)
            {
                parent[i] = i;
            }

            int bands = HashCount / RowsPerBand;
            for (int band = 0; band < bands; band++)
            {
                // bucket key -> the first record that had it
                Dictionary<ulong, List<int>> buckets = new Dictionary<ulong, List<int>>();
                for (int i = 0; i < n; i++)
                {
                    ulong key = (ulong) band * 0x9E3779B97F4A7C15UL;
                    for (int r = 0; r < RowsPerBand; r++)
                    {
                        key = Mix(key ^ signatures[i][band * RowsPerBand + r]);
                    }
                    List<int> members;
                    if (!buckets.TryGetValue(key, out members))
                    {
                        members = new List<int>();
                        buckets[key] = members;
                    }
                    members.Add(i);
                }
                foreach (List<int> members in buckets.Values)
                {
                    if (members.Count < 2 || members.Count > 2000)
                    {
                        continue;   // a giant bucket means "empty message"-style junk; skip it
                    }
                    // Small buckets: compare every pair. Big ones: compare each with the first
                    // (a big bucket is usually one huge campaign, so that catches it).
                    int stride = members.Count <= 60 ? members.Count : 1;
                    for (int x = 0; x < stride; x++)
                    {
                        for (int y = x + 1; y < members.Count; y++)
                        {
                            int a = members[x];
                            int b = members[y];
                            if (Find(parent, a) == Find(parent, b))
                            {
                                continue;
                            }
                            if (Jaccard(shingles[a], shingles[b]) >= Threshold)
                            {
                                parent[Find(parent, a)] = Find(parent, b);
                            }
                        }
                    }
                }
            }

            int[] group = new int[n];
            for (int i = 0; i < n; i++)
            {
                group[i] = Find(parent, i);
            }
            return group;
        }

        // The set of 3-word shingles, each stored as a 64-bit hash to save memory.
        // Messages under 6 words use their single words instead (3-word runs would be too few).
        public static HashSet<ulong> Shingles(MessageRecord r)
        {
            string text = r.FullText();
            if (text.Length > MaxChars)
            {
                text = text.Substring(0, MaxChars);
            }
            text = Regex.Replace(text.ToLowerInvariant(), "[0-9]", "0");
            MatchCollection matches = Regex.Matches(text, "[a-z0-9]+");
            List<string> words = new List<string>(matches.Count);
            foreach (Match m in matches)
            {
                words.Add(m.Value);
            }
            HashSet<ulong> set = new HashSet<ulong>();
            if (words.Count < 6)
            {
                foreach (string w in words)
                {
                    set.Add(Hash(w));
                }
                return set;
            }
            for (int i = 0; i + 2 < words.Count; i++)
            {
                set.Add(Hash(words[i] + " " + words[i + 1] + " " + words[i + 2]));
            }
            return set;
        }

        // Shared shingles / all shingles (see the class comment). 1.0 for two empty sets.
        public static double Jaccard(HashSet<ulong> a, HashSet<ulong> b)
        {
            if (a.Count == 0 && b.Count == 0)
            {
                return 1.0;
            }
            HashSet<ulong> small = a.Count <= b.Count ? a : b;
            HashSet<ulong> large = a.Count <= b.Count ? b : a;
            int shared = 0;
            foreach (ulong x in small)
            {
                if (large.Contains(x))
                {
                    shared++;
                }
            }
            return shared / (double) (a.Count + b.Count - shared);
        }

        // For each of the 64 "random numberings", the smallest number among the message's shingles.
        // Numbering k gives shingle s the number Mix(s ^ seed[k]): a fixed, random-looking function.
        private static ulong[] Signature(HashSet<ulong> set, ulong[] seeds)
        {
            ulong[] sig = new ulong[HashCount];
            for (int k = 0; k < HashCount; k++)
            {
                sig[k] = ulong.MaxValue;
            }
            foreach (ulong s in set)
            {
                for (int k = 0; k < HashCount; k++)
                {
                    ulong v = Mix(s ^ seeds[k]);
                    if (v < sig[k])
                    {
                        sig[k] = v;
                    }
                }
            }
            return sig;
        }

        // The 64 fixed "random numberings" (the same every run, so groups are always the same).
        private static ulong[] MakeSeeds()
        {
            ulong[] seeds = new ulong[HashCount];
            ulong x = 0x2545F4914F6CDD1DUL;
            for (int k = 0; k < HashCount; k++)
            {
                x = Mix(x + 0x9E3779B97F4A7C15UL);
                seeds[k] = x;
            }
            return seeds;
        }

        // FNV-1a: a simple, well-known way to turn a string into a 64-bit number.
        private static ulong Hash(string s)
        {
            ulong h = 14695981039346656037UL;
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            foreach (byte b in bytes)
            {
                h ^= b;
                h *= 1099511628211UL;
            }
            return Mix(h);
        }

        // "SplitMix64" finalizer: scrambles the bits of a number so similar inputs give
        // unrelated outputs. (Same idea as the hash functions inside Java's HashMap.)
        private static ulong Mix(ulong z)
        {
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }

        // Union-find: the group a record belongs to (the record at the top of its chain).
        private static int Find(int[] parent, int i)
        {
            while (parent[i] != i)
            {
                parent[i] = parent[parent[i]];   // shortcut the path as we go
                i = parent[i];
            }
            return i;
        }
    }
}
