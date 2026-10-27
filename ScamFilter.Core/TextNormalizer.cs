using System;
using System.Collections.Generic;
using System.Text;

namespace ScamFilter
{
    /*
     * Breaks message text into n-grams: the raw material for the text features (see Featurizer).
     *
     * An "n-gram" is just a run of n things in a row:
     *   word 1-grams ("unigrams"):  "verify", "your", "account"
     *   word 2-grams ("bigrams"):   "verify your", "your account"
     *   letter 3-grams:             "ver", "eri", "rif", "ify"
     *
     * ============================================================================
     *  STEP 1: NORMALIZE  (make text that means the same thing look the same)
     * ============================================================================
     *   - remove invisible characters, which scammers slip inside words so filters don't
     *     recognize them: "pay[zero-width space]pal" -> "paypal"
     *   - fold "fancy" letters into plain ones (Unicode NFKC): full-width letters, ligatures,
     *     circled and math-style letters all become ordinary letters
     *   - SHOUTING -> "zcapsz"       a word of 3+ letters written in ALL CAPS also adds the token
     *                                "zcapsz", so the model can learn how much shouting is normal
     *   - lowercase                  "URGENT" and "urgent" are the same word
     *   - look-alike letters         Cyrillic and Greek letters that look exactly like Latin ones,
     *                                used to disguise words ("UPS" spelled with a Cyrillic P and S),
     *                                become the Latin letter, and the word adds the token "zmixedz".
     *                                Only words that MIX the two alphabets are changed, so real
     *                                Russian or Greek text is left alone.
     *   - links  -> "zurlz"          the text model learns THAT there's a link. WHICH link is
     *                                judged by the metadata flags (MetadataFeatures), so the model
     *                                can't just memorize a list of scam domains.
     *   - emails -> "zemailz"
     *   - every digit -> 0           "code 482913" and "code 105577" both become "code 000000",
     *                                so the model learns "a 6-digit code", not one specific code
     *   - all whitespace -> one space
     * ("zurlz" and "zemailz" are deliberately strange so they can't collide with real words.)
     *
     * ============================================================================
     *  STEP 2: TOKENIZE  (split into pieces)
     * ============================================================================
     *   Runs of letters/digits are tokens. Money and pressure symbols are tokens of their own,
     *   because they're useful signals: $ (dollar), the pound and euro signs, % and !.
     *   All other punctuation is dropped.
     *
     * ============================================================================
     *  STEP 3: N-GRAMS  (with a prefix so the three kinds never collide)
     * ============================================================================
     *   "w:token"            each word
     *   "b:token1 token2"    each pair of neighboring words
     *   "c:xyz"              each 3-, 4-, and 5-letter piece inside a word. A space is added
     *                        at each end of the word first, so pieces at the edges are
     *                        distinct: " ve" only comes from words that START with "ve".
     *
     * Why letter pieces? They make the model tough against misspellings and OCR errors.
     * "verify" and "verlfy" share no whole word, but they still share pieces like " ve", "ver",
     * " ver" and "fy ", so the model recognizes most of the word anyway.
     */
    public static class TextNormalizer
    {
        // Symbols kept as tokens (see STEP 2). Written as numbers: 0x00A3 is the pound sign, 0x20AC the euro sign.
        private const char Pound = (char) 0x00A3;
        private const char Euro = (char) 0x20AC;

        // Is this one of the symbols that's kept as its own token ($, !, %, pound, euro)?
        private static bool IsSymbolToken(char c)
        {
            return c == '$' || c == '!' || c == '%' || c == Pound || c == Euro;
        }

        /*
         * Look-alike letters, as pairs: { look-alike, plain Latin letter, look-alike, Latin, ... }.
         * The look-alikes are written as numbers because they're impossible to tell apart from
         * Latin letters on screen (that's the whole trick). These are the LOWERCASE forms, since
         * the text is lowercased first: Cyrillic capital P becomes 0x0440 and then 'p'.
         *   Cyrillic: 0430 a, 0432 b (capital looks like B), 0435 e, 043A k, 043C m (capital M),
         *             043D h (capital H), 043E o, 0440 p, 0441 c, 0442 t (capital T), 0443 y,
         *             0445 x, 0455 s, 0456 i, 0458 j, 04BB h, 04AF y, 04CF l, 0501 d, 051B q, 051D w
         *   Greek:    03B1 a, 03B2 b, 03B5 e, 03B9 i, 03BA k, 03BD v, 03BF o, 03C1 p, 03C4 t,
         *             03C5 u, 03C7 x
         */
        private static readonly int[] LookAlikePairs =
        {
            0x0430, 'a', 0x0432, 'b', 0x0435, 'e', 0x043A, 'k', 0x043C, 'm', 0x043D, 'h', 0x043E, 'o',
            0x0440, 'p', 0x0441, 'c', 0x0442, 't', 0x0443, 'y', 0x0445, 'x', 0x0455, 's', 0x0456, 'i',
            0x0458, 'j', 0x04BB, 'h', 0x04AF, 'y', 0x04CF, 'l', 0x0501, 'd', 0x051B, 'q', 0x051D, 'w',
            0x03B1, 'a', 0x03B2, 'b', 0x03B5, 'e', 0x03B9, 'i', 0x03BA, 'k', 0x03BD, 'v', 0x03BF, 'o',
            0x03C1, 'p', 0x03C4, 't', 0x03C5, 'u', 0x03C7, 'x'
        };
        // The table above as a dictionary: look-alike letter -> the plain letter it imitates.
        private static readonly Dictionary<char, char> LookAlikes = BuildLookAlikes();

        // Builds LookAlikes from the pairs in LookAlikePairs.
        private static Dictionary<char, char> BuildLookAlikes()
        {
            Dictionary<char, char> map = new Dictionary<char, char>();
            for (int i = 0; i < LookAlikePairs.Length; i += 2)
            {
                map[(char) LookAlikePairs[i]] = (char) LookAlikePairs[i + 1];
            }
            return map;
        }

        // Marker words added to the text (see MarkShouting and FoldLookAlikes). They're
        // spelled oddly on purpose, so no real word is ever mistaken for one.
        public const string CapsToken = "zcapsz";
        public const string MixedToken = "zmixedz";

        /*
         * Adds " zcapsz" after every ALL-CAPS word of 3 or more letters.
         * "URGENT: verify NOW" -> "URGENT zcapsz: verify NOW zcapsz"
         * Runs BEFORE lowercasing (afterwards the capitals are gone).
         */
        private static string MarkShouting(string s)
        {
            StringBuilder sb = null;
            int i = 0;
            while (i < s.Length)
            {
                if (!char.IsLetter(s[i]))
                {
                    if (sb != null)
                    {
                        sb.Append(s[i]);
                    }
                    i++;
                    continue;
                }
                int start = i;
                bool allUpper = true;
                while (i < s.Length && char.IsLetter(s[i]))
                {
                    if (!char.IsUpper(s[i]))
                    {
                        allUpper = false;
                    }
                    i++;
                }
                bool shout = allUpper && i - start >= 3;
                if (shout && sb == null)
                {
                    sb = new StringBuilder(s.Length + 64);
                    sb.Append(s, 0, start);   // copy everything before the first shouted word
                }
                if (sb != null)
                {
                    sb.Append(s, start, i - start);
                    if (shout)
                    {
                        sb.Append(' ').Append(CapsToken).Append(' ');
                    }
                }
            }
            return sb == null ? s : sb.ToString();
        }

        /*
         * Replaces look-alike letters with Latin ones, but only inside words that mix them with
         * real Latin letters, and adds " zmixedz" after each such word. (Lowercase text only.)
         * "ups" with a Cyrillic p and s -> "ups zmixedz"
         */
        private static string FoldLookAlikes(string s)
        {
            StringBuilder sb = null;
            int i = 0;
            while (i < s.Length)
            {
                if (!char.IsLetter(s[i]))
                {
                    if (sb != null)
                    {
                        sb.Append(s[i]);
                    }
                    i++;
                    continue;
                }
                int start = i;
                bool hasLatin = false;
                bool hasLookAlike = false;
                while (i < s.Length && char.IsLetter(s[i]))
                {
                    char c = s[i];
                    if (c >= 'a' && c <= 'z')
                    {
                        hasLatin = true;
                    }
                    else if (LookAlikes.ContainsKey(c))
                    {
                        hasLookAlike = true;
                    }
                    i++;
                }
                bool mixed = hasLatin && hasLookAlike;
                if (mixed && sb == null)
                {
                    sb = new StringBuilder(s.Length + 64);
                    sb.Append(s, 0, start);
                }
                if (sb != null)
                {
                    for (int k = start; k < i; k++)
                    {
                        char plain;
                        sb.Append(mixed && LookAlikes.TryGetValue(s[k], out plain) ? plain : s[k]);
                    }
                    if (mixed)
                    {
                        sb.Append(' ').Append(MixedToken).Append(' ');
                    }
                }
            }
            return sb == null ? s : sb.ToString();
        }

        public const int CharMin = 3;   // shortest letter piece
        public const int CharMax = 5;   // longest letter piece

        /*
         * Characters that take up no space on screen. They're legitimately used in a few
         * languages, but in scam messages they're mostly there to break up words like "PayPal"
         * so simple filters miss them. Written as \u codes because they're invisible.
         *   00AD soft hyphen, 034F combining grapheme joiner, 180E Mongolian vowel separator,
         *   200B-200F zero-width spaces/joiners and direction marks, 2060-2064 word joiner and
         *   invisible math operators, FEFF zero-width no-break space
         */
        public static string RemoveInvisible(string s)
        {
            if (string.IsNullOrEmpty(s))
            {
                return s ?? "";
            }
            StringBuilder sb = null;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bool invisible = c == '\u00AD' || c == '\u034F' || c == '\u180E'
                    || (c >= '\u200B' && c <= '\u200F') || (c >= '\u2060' && c <= '\u2064') || c == '\uFEFF';
                if (invisible)
                {
                    if (sb == null)
                    {
                        sb = new StringBuilder(s.Length);
                        sb.Append(s, 0, i);   // copy everything before the first invisible character
                    }
                }
                else if (sb != null)
                {
                    sb.Append(c);
                }
            }
            return sb == null ? s : sb.ToString();
        }

        // Unicode NFKC: full-width letters (like the ones in some scam texts) -> "Paypal",
        // and ligatures like the single character "fi" -> the two letters "fi".
        private static string FoldFancyLetters(string s)
        {
            try
            {
                return s.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                return s;   // broken text (half of an emoji pair, say) can't be normalized; use it as-is
            }
        }

        // Step 1. "Your code is 482913! https://x.com" -> "your code is 000000! zurlz"
        public static string Normalize(string raw)
        {
            if (raw == null)
            {
                return "";
            }
            // Links go first, so a link written in capitals isn't mistaken for shouting.
            string withoutLinks = UrlAnalyzer.ReplaceLinks(FoldFancyLetters(RemoveInvisible(raw)));
            string s = FoldLookAlikes(MarkShouting(withoutLinks).ToLowerInvariant());
            StringBuilder sb = new StringBuilder(s.Length);
            bool lastWasSpace = true;   // starts true so leading whitespace is skipped
            foreach (char c in s)
            {
                if (char.IsDigit(c))
                {
                    sb.Append('0');
                    lastWasSpace = false;
                }
                else if (char.IsWhiteSpace(c))
                {
                    if (!lastWasSpace)   // collapse runs of whitespace into a single space
                    {
                        sb.Append(' ');
                        lastWasSpace = true;
                    }
                }
                else
                {
                    sb.Append(c);
                    lastWasSpace = false;
                }
            }
            return sb.ToString().Trim();
        }

        // Step 2. "pay $50 now!" -> [pay, $, 00, now, !]   ("save 50%" -> [save, 00, %])
        public static List<string> Tokens(string normalized)
        {
            List<string> tokens = new List<string>();
            StringBuilder current = new StringBuilder();
            foreach (char c in normalized)
            {
                if (char.IsLetterOrDigit(c))
                {
                    current.Append(c);
                }
                else
                {
                    // Anything else ends the current token...
                    if (current.Length > 0)
                    {
                        tokens.Add(current.ToString());
                        current.Clear();
                    }
                    // ...and money and pressure symbols are kept as tokens themselves.
                    if (IsSymbolToken(c))
                    {
                        tokens.Add(c.ToString());
                    }
                }
            }
            if (current.Length > 0)
            {
                tokens.Add(current.ToString());
            }
            return tokens;
        }

        /*
         * Steps 1-3. Adds every n-gram in the text to `counts` (n-gram -> times it appears).
         *
         * Example: "Verify now" adds
         *   w:verify  w:now  b:verify now
         *   c: ve  c:ver  c:eri  ... c:fy   (pieces of " verify ")
         *   c: no  c:now  c:ow   ...        (pieces of " now ")
         */
        public static void AddFeatures(string rawText, Dictionary<string, int> counts)
        {
            List<string> toks = Tokens(Normalize(rawText));
            string previous = null;
            foreach (string token in toks)
            {
                Increment(counts, "w:" + token);
                if (previous != null)
                {
                    Increment(counts, "b:" + previous + " " + token);
                }
                previous = token;

                // Letter pieces only for real words (not the symbol tokens).
                if (char.IsLetterOrDigit(token[0]))
                {
                    string padded = " " + token + " ";
                    for (int n = CharMin; n <= CharMax; n++)
                    {
                        for (int start = 0; start + n <= padded.Length; start++)
                        {
                            Increment(counts, "c:" + padded.Substring(start, n));   // Substring(start, LENGTH)
                        }
                    }
                }
            }
        }

        // Adds 1 to a count, starting from 0 the first time.
        private static void Increment(Dictionary<string, int> counts, string key)
        {
            int old;
            counts.TryGetValue(key, out old);   // old is 0 if the key isn't there yet
            counts[key] = old + 1;
        }
    }
}
