using System;
using System.Collections.Generic;

namespace ScamFilter
{
    /*
     * Turns a message's text into the list of numbers the model needs (its text features).
     *
     * ============================================================================
     *  WHY NUMBERS?
     * ============================================================================
     * The model can only multiply and add (see ScamModel), so text has to become numbers.
     *
     * Step 1: build a VOCABULARY. TextNormalizer breaks every training message into
     *         n-grams (words, word pairs, and short letter pieces). Each distinct n-gram that's
     *         common enough gets an index number:
     *             0 -> "w:your"     1 -> "w:account"     2 -> "b:verify your"     ...
     * Step 2: a message becomes a vector (a long list of numbers) with one slot per vocabulary
     *         entry. Slot j holds how strongly n-gram j appears in this message. For almost
     *         every slot that's 0, which is why it's stored as a SparseVector.
     *
     * This is called a "bag of words": word order is mostly thrown away, as if you cut the
     * message into words and shook them in a bag (the word pairs keep a little of the order).
     * It sounds crude, but for spotting scams it works surprisingly well.
     *
     * ============================================================================
     *  TF-IDF: HOW MUCH EACH N-GRAM COUNTS
     * ============================================================================
     * Raw counts aren't great. "the" is everywhere and tells you nothing; "gift card" is rare
     * and tells you a lot. TF-IDF scales each count by how rare the n-gram is:
     *
     *     x_j = tf_j * ln(N / df_j)
     *
     *     tf_j  = "term frequency": how many times n-gram j appears in THIS message
     *     N     = how many training messages there are
     *     df_j  = "document frequency": how many training messages contain n-gram j
     *     ln(N / df_j) is the "IDF" (inverse document frequency) part
     *
     * Example with N = 1000 training messages:
     *     "the"        in 900 of them   ->  idf = ln(1000/900) = 0.11   (barely counts)
     *     "gift card"  in  20 of them   ->  idf = ln(1000/20)  = 3.91   (counts a lot)
     *     something in all 1000         ->  idf = ln(1)        = 0      (no information)
     *
     * ============================================================================
     *  L2 NORMALIZATION: MAKING LONG AND SHORT MESSAGES COMPARABLE
     * ============================================================================
     * A 500-word email has much bigger counts than a 10-word text, so its score would swing
     * further just for being long. So after computing x, divide it by its length:
     *
     *     ||x|| = sqrt(x_1^2 + x_2^2 + ...)          x <- x / ||x||
     *
     * Now every message's vector has length 1, and only the MIX of n-grams matters.
     *
     * ============================================================================
     *  TWO REFINEMENTS (both on by default; picked by cross-validation, see TrainingSettings)
     * ============================================================================
     * SUBLINEAR TF: a repeated n-gram counts 1 + ln(tf) instead of tf. Said once it counts 1,
     * twice 1.69, ten times 3.30. An email that says "click here" six times isn't six times
     * more suspicious than one that says it once.
     *
     * TYPE COPIES: every n-gram is counted twice, once as itself and once as an emails-only
     * or texts-only copy ("E|w:verify" or "T|w:verify"). The shared copy learns what a word
     * means everywhere; the typed copy learns what's different about it in that kind of
     * message. "Reply STOP to opt out" is routine in a real store's text but odd in an email,
     * and this lets the model learn both.
     *
     * Both are saved with the model, so a saved model always reads text the way it was trained.
     *
     * ============================================================================
     *  NO PEEKING AT THE TEST SET
     * ============================================================================
     * The vocabulary and the df counts come from the TRAINING set only. If validation or test
     * messages helped build them, information about the "final exam" would leak into the model
     * (this is called DATA LEAKAGE), and the test score would look better than it really is.
     * New n-grams that weren't in the training vocabulary are simply ignored.
     */
    public class Featurizer
    {
        private readonly Dictionary<string, int> vocab;   // n-gram -> its index
        private readonly string[] terms;                  // index -> n-gram
        private readonly double[] idf;                    // index -> its ln(N / df) value

        // How text is counted (see "TWO REFINEMENTS" above). Saved with the model.
        public readonly bool SublinearTf;
        public readonly bool TypeCopies;

        // A featurizer for an existing vocabulary (used when loading a saved model). Build makes
        // a new one from training data.
        public Featurizer(string[] terms, double[] idf, bool sublinearTf, bool typeCopies)
        {
            this.terms = terms;
            this.idf = idf;
            SublinearTf = sublinearTf;
            TypeCopies = typeCopies;
            vocab = new Dictionary<string, int>(terms.Length * 2);
            for (int i = 0; i < terms.Length; i++)
            {
                vocab[terms[i]] = i;
            }
        }

        /*
         * Builds the vocabulary from the training records.
         *
         * Keeps n-grams that appear in at least minDf messages (rarer ones are mostly noise
         * and can't teach a general pattern), then keeps the maxFeatures most common of those.
         */
        public static Featurizer Build(List<MessageRecord> records, int minDf, int maxFeatures, bool sublinearTf, bool typeCopies)
        {
            // Count, for every n-gram, how many messages contain it (df). A message that says
            // "verify" three times still only counts once here.
            Dictionary<string, int> docFreq = new Dictionary<string, int>();
            foreach (MessageRecord r in records)
            {
                Dictionary<string, int> tf = CountTerms(r, typeCopies);
                foreach (string term in tf.Keys)
                {
                    int old;
                    docFreq.TryGetValue(term, out old);
                    docFreq[term] = old + 1;
                }
            }

            List<string> kept = new List<string>();
            foreach (KeyValuePair<string, int> e in docFreq)
            {
                if (e.Value >= minDf)
                {
                    kept.Add(e.Key);
                }
            }
            // Most common first; ties broken alphabetically (by character code), so every run
            // builds the exact same vocabulary.
            kept.Sort((a, b) =>
            {
                int c = docFreq[b].CompareTo(docFreq[a]);
                return c != 0 ? c : string.CompareOrdinal(a, b);
            });
            if (kept.Count > maxFeatures)
            {
                kept = kept.GetRange(0, maxFeatures);
            }

            string[] terms = new string[kept.Count];
            double[] idf = new double[kept.Count];
            double n = records.Count;
            for (int i = 0; i < terms.Length; i++)
            {
                terms[i] = kept[i];
                idf[i] = Math.Log(n / docFreq[terms[i]]);   // ln(N / df)
            }
            return new Featurizer(terms, idf, sublinearTf, typeCopies);
        }

        /*
         * Only the first MaxTextChars characters of a message are turned into features. A scam
         * shows its hand early (the "verify your account" is in the first paragraphs, not the
         * legal footer), and long emails would otherwise cost lots of memory and time for
         * little gain. The same limit applies when training and when checking, so the model
         * always sees messages the same way.
         */
        public const int MaxTextChars = 3000;

        // Raw n-gram counts for one record: n-gram -> tf (times it appears).
        public static Dictionary<string, int> CountTerms(MessageRecord r, bool typeCopies)
        {
            Dictionary<string, int> counts = new Dictionary<string, int>();
            string text = r.FullText();
            if (text.Length > MaxTextChars)
            {
                text = text.Substring(0, MaxTextChars);
            }
            TextNormalizer.AddFeatures(text, counts);
            if (typeCopies)
            {
                string prefix = r.IsEmail() ? "E|" : "T|";
                // A copy of the list, because the loop adds to `counts` as it goes.
                List<KeyValuePair<string, int>> shared = new List<KeyValuePair<string, int>>(counts);
                foreach (KeyValuePair<string, int> e in shared)
                {
                    counts[prefix + e.Key] = e.Value;
                }
            }
            return counts;
        }

        /*
         * The record's TF-IDF vector, L2-normalized. N-grams outside the vocabulary are ignored.
         * The entries aren't sorted by index; a dot product doesn't care about order.
         */
        public SparseVector Transform(MessageRecord r)
        {
            Dictionary<string, int> tf = CountTerms(r, TypeCopies);
            int[] idx = new int[tf.Count];
            double[] val = new double[tf.Count];
            int count = 0;
            foreach (KeyValuePair<string, int> e in tf)
            {
                int index;
                if (vocab.TryGetValue(e.Key, out index) && idf[index] > 0.0)
                {
                    idx[count] = index;
                    double tfValue = SublinearTf ? 1.0 + Math.Log(e.Value) : e.Value;
                    val[count] = tfValue * idf[index];   // tf * idf
                    count++;
                }
            }

            // Divide by the vector's length so it ends up with length 1.
            double sumSquares = 0.0;
            for (int k = 0; k < count; k++)
            {
                sumSquares += val[k] * val[k];
            }
            if (sumSquares > 0.0)
            {
                double norm = Math.Sqrt(sumSquares);
                for (int k = 0; k < count; k++)
                {
                    val[k] = val[k] / norm;
                }
            }
            // Trim the arrays down to the entries actually used.
            Array.Resize(ref idx, count);
            Array.Resize(ref val, count);
            return new SparseVector(idx, val);
        }

        // How many text features (vocabulary entries) there are.
        public int Size
        {
            get { return terms.Length; }
        }

        // The n-gram that feature number `index` stands for, like "w:verify".
        public string Term(int index)
        {
            return terms[index];
        }

        // Feature `index`'s IDF number, ln(N / df) (see the class comment).
        public double Idf(int index)
        {
            return idf[index];
        }
    }
}
