using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ScamFilter
{
    /*
     * The model itself: LOGISTIC REGRESSION. This class is how a guess gets made.
     * (How the weights get their values is LogisticTrainer's job.)
     *
     * ============================================================================
     *  THE IDEA: ADD UP WEIGHTED EVIDENCE
     * ============================================================================
     *
     * Every message gets turned into FEATURES: numbers that describe it.
     *   - text features, one per word or word-piece (see Featurizer). Example: how strongly
     *     the message contains the phrase "verify your".
     *   - metadata flags (see MetadataFeatures). Example: 1 if a link imitates a brand, else 0.
     *
     * Every feature has a WEIGHT: a number saying how much that feature counts as evidence.
     *   positive weight  -> evidence FOR scam       ("verify your" might get +1.8)
     *   negative weight  -> evidence AGAINST scam   (sender is in your contacts: -2.0)
     *   near zero        -> doesn't matter          ("the" ends up around 0)
     *
     * To score a message, multiply each feature by its weight and add it all up:
     *
     *     z = (w1*x1 + w2*x2 + ...)  +  b  +  (m1*f1 + m2*f2 + ...)
     *
     *     x = the text features       w = their weights (learned during training)
     *     f = the metadata flags      m = their weights (hand-set in MetadataFeatures for now)
     *     b = the BIAS: a starting score before any evidence. It soaks up the overall
     *         scam-to-not-scam ratio of the training data.
     *
     * z can be any number. Big positive = lots of scam evidence. Big negative = lots of
     * evidence it's fine. 0 = a toss-up.
     *
     * ============================================================================
     *  TURNING THE SCORE INTO A PROBABILITY: THE SIGMOID
     * ============================================================================
     *
     *     p = 1 / (1 + e^(-z))
     *
     * This "squashes" any z into the range 0 to 1, so p reads as "the chance it's a scam":
     *
     *       z :   -4      -2      0      +2      +4
     *       p :  0.02    0.12   0.50    0.88    0.98
     *
     * Technically, z is the "log-odds" of scam:  z = ln(p / (1 - p)).
     * The useful consequence: adding +1 to z multiplies the odds of "scam" by e (about 2.7).
     * So a weight of +2.5 multiplies the odds by e^2.5, about 12. That's how to read any
     * weight in this project.
     *
     * Worked example: a text whose words add up to z = -0.4, plus a look-alike domain (+2.5)
     * and a risky TLD (+0.75):
     *     z = -0.4 + 2.5 + 0.75 = 2.85
     *     p = 1 / (1 + e^-2.85) = 0.945       -> 94.5% likely a scam
     *
     * ============================================================================
     *  "NEURAL NETWORK" TERMS
     * ============================================================================
     * In neural-network language this is a single neuron with a sigmoid activation and no
     * hidden layers. A bigger network could learn combinations of features, but with a few
     * thousand examples it mostly just memorizes. One neuron is small, fast, and readable:
     * every weight belongs to exactly one n-gram or flag, so you can see why it decided.
     *
     * ============================================================================
     *  BANDS
     * ============================================================================
     *     p >= THigh          -> UNSAFE
     *     TLow <= p < THigh   -> CAUTION     (the model isn't confident either way)
     *     p < TLow            -> SAFE
     * ThresholdPicker chooses TLow and THigh from data; they aren't set by hand.
     */
    public class ScamModel
    {
        // The three bands a verdict can have.
        public const string Safe = "SAFE";
        public const string Caution = "CAUTION";
        public const string Unsafe = "UNSAFE";

        /*
         * The number goes up whenever the way text is turned into features changes, because a
         * model trained the old way would look up the wrong n-grams.
         *   1  version 1.0 and 1.1
         *   2  version 1.2: shouting and look-alike-letter tokens, hidden email text removed
         */
        private const string FileHeader = "SCAMMODEL 3";

        // False for a missing file, a damaged one, or one saved by an older version.
        public static bool HasCurrentFormat(string path)
        {
            if (!File.Exists(path))
            {
                return false;
            }
            try
            {
                StreamReader reader = DataFiles.OpenReader(path);
                string header = DataFiles.StripBom(reader.ReadLine());
                reader.Close();
                return header == FileHeader;
            }
            catch (IOException)
            {
                return false;
            }
        }

        // Knows the vocabulary: which n-gram goes with which text weight.
        public readonly Featurizer Featurizer;

        // w: one weight per text feature. TextWeights[j] goes with Featurizer.Term(j).
        public double[] TextWeights;

        // b: the starting score before any evidence.
        public double Bias;

        // m: one weight per metadata flag. MetaWeights[k] goes with MetadataFeatures.Names[k].
        public double[] MetaWeights;

        // Below TLow -> SAFE.
        public double TLow = 0.3;

        // At or above THigh -> UNSAFE. In between -> CAUTION.
        public double THigh = 0.7;

        // A brand-new, untrained model: every text weight starts at 0, meaning "no opinion yet".
        public ScamModel(Featurizer featurizer, double[] metaWeights)
        {
            Featurizer = featurizer;
            TextWeights = new double[featurizer.Size];
            Bias = 0.0;
            MetaWeights = metaWeights;
        }

        /*
         * p = 1 / (1 + e^(-z)), written so it never overflows.
         *
         * For a very negative z (say -1000), e^(-z) = e^1000 is too big for a double and
         * becomes Infinity. So for negative z we use the same function rearranged:
         * multiply top and bottom by e^z to get e^z / (1 + e^z). Same answer, no overflow.
         */
        public static double Sigmoid(double z)
        {
            if (z >= 0.0)
            {
                return 1.0 / (1.0 + Math.Exp(-z));
            }
            double e = Math.Exp(z);
            return e / (1.0 + e);
        }

        // z = (text features . text weights) + bias + (flags . metadata weights)
        public double Logit(SparseVector x, double[] flags)
        {
            double z = x.Dot(TextWeights) + Bias;
            for (int k = 0; k < flags.Length; k++)
            {
                z += MetaWeights[k] * flags[k];
            }
            return z;
        }

        // The full guess for one message: features -> z -> p.
        public double Probability(MessageRecord r)
        {
            return Sigmoid(Logit(Featurizer.Transform(r), MetadataFeatures.Compute(r)));
        }

        // Which band a probability falls in.
        public string Band(double p)
        {
            if (p >= THigh)
            {
                return Unsafe;
            }
            if (p >= TLow)
            {
                return Caution;
            }
            return Safe;
        }

        // ------------------------------------------------------------------
        // Explanations
        //
        // Because z is just a sum, every feature's share of the decision is exactly
        // (its weight) x (its value). The biggest shares are the "reasons".
        // ------------------------------------------------------------------

        /*
         * The k biggest contributions to z.
         * towardScam = true lists what pushed toward scam; false lists what pushed toward safe.
         * Tiny contributions (under 0.05) are skipped as noise.
         */
        public List<Reason> Explain(MessageRecord r, int k, bool towardScam)
        {
            SparseVector x = Featurizer.Transform(r);
            double[] flags = MetadataFeatures.Compute(r);
            List<Reason> all = new List<Reason>();
            // With email/text copies (see Featurizer) a word has two features, "w:verify" and
            // "E|w:verify". They share a label, so their shares are added up into one reason.
            Dictionary<string, double> byLabel = new Dictionary<string, double>();
            List<string> labelOrder = new List<string>();
            for (int i = 0; i < x.Size; i++)
            {
                int j = x.Indices[i];
                string label = TermLabel(Featurizer.Term(j));
                double share;
                if (!byLabel.TryGetValue(label, out share))
                {
                    labelOrder.Add(label);
                }
                byLabel[label] = share + TextWeights[j] * x.Values[i];
            }
            foreach (string label in labelOrder)
            {
                all.Add(new Reason(label, byLabel[label], false));
            }
            for (int i = 0; i < flags.Length; i++)
            {
                if (flags[i] != 0.0 && MetaWeights[i] != 0.0)
                {
                    all.Add(new Reason(MetadataFeatures.Reasons[i], MetaWeights[i] * flags[i], true));
                }
            }
            // OrderBy keeps equal items in their original order (a "stable" sort), like Java's sort.
            IEnumerable<Reason> sorted = towardScam
                ? all.OrderByDescending(c => c.Value)   // biggest first
                : all.OrderBy(c => c.Value);           // most negative first
            List<Reason> output = new List<Reason>();
            foreach (Reason c in sorted)
            {
                if (output.Count >= k)
                {
                    break;
                }
                bool rightDirection = towardScam ? c.Value > 0.05 : c.Value < -0.05;
                if (rightDirection)
                {
                    output.Add(c);
                }
            }
            return output;
        }

        /*
         * Turns an internal feature name into something readable:
         *   "w:verify"       -> word "verify"
         *   "b:verify your"  -> phrase "verify your"
         *   "c: ver"         -> text piece "_ver"   (the _ marks the start or end of a word)
         * The emails-only and texts-only copies ("E|w:verify", "T|w:verify") read the same as
         * the shared feature: to a person they're the same word.
         */
        public static string TermLabel(string term)
        {
            if (term.Length > 2 && term[1] == '|')
            {
                term = term.Substring(2);
            }
            string body = term.Substring(2).Replace("zurlz", "[link]").Replace("zemailz", "[email]");
            if (term.StartsWith("w:", StringComparison.Ordinal))
            {
                return "word \"" + body + "\"";
            }
            if (term.StartsWith("b:", StringComparison.Ordinal))
            {
                return "phrase \"" + body + "\"";
            }
            return "text piece \"" + body.Replace(' ', '_') + "\"";
        }

        // TermLabel plus which copy it is, for reports: word "verify" (emails only).
        public static string ReportLabel(string term)
        {
            string label = TermLabel(term);
            if (term.StartsWith("E|", StringComparison.Ordinal))
            {
                return label + " (emails only)";
            }
            if (term.StartsWith("T|", StringComparison.Ordinal))
            {
                return label + " (texts only)";
            }
            return label;
        }

        /*
         * Prints the text features with the strongest weights in each direction: what the model
         * actually learned. Check this after every training run. If the top features are junk
         * (say, a signature line that only one dataset has), the model found a shortcut that
         * tells your SOURCES apart instead of learning what scams look like.
         */
        public void PrintTopWeights(int k, Action<string> log)
        {
            double[] w = TextWeights;
            List<int> order = Enumerable.Range(0, w.Length).OrderByDescending(j => w[j]).ToList();
            log("");
            log("Top text features pushing toward SCAM:");
            for (int i = 0; i < k && i < order.Count; i++)
            {
                int j = order[i];
                if (w[j] <= 0.0)
                {
                    break;
                }
                log("  " + Format.Signed(w[j], 3) + "  " + ReportLabel(Featurizer.Term(j)));
            }
            log("Top text features pushing toward NOT SCAM:");
            for (int i = 0; i < k && i < order.Count; i++)
            {
                int j = order[order.Count - 1 - i];   // walk from the most negative end
                if (w[j] >= 0.0)
                {
                    break;
                }
                log("  " + Format.Signed(w[j], 3) + "  " + ReportLabel(Featurizer.Term(j)));
            }
        }

        // ------------------------------------------------------------------
        // Saving and loading
        //
        // A trained model is just numbers, so it's saved as a plain text file you can open
        // and read. Tab-separated, in this order:
        //
        //   SCAMMODEL 3                      (header, so we never load the wrong kind of file)
        //   t_low    <number>
        //   t_high   <number>
        //   bias     <number>
        //   sublinear_tf  0 or 1             (how text is counted; see Featurizer)
        //   type_copies   0 or 1
        //   meta     <how many flags>
        //   <flag name>   <weight>           (one line per metadata flag)
        //   text     <how many n-grams>
        //   <n-gram>   <idf>   <weight>      (one line per text feature; idf is explained in Featurizer)
        // ------------------------------------------------------------------

        public void Save(string path)
        {
            string folder = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }
            // Written to a temporary file first, then swapped in, so nothing ever reads a half-written
            // model. (The temporary name includes this program's process ID, so two ScamFilter windows
            // never write into the same one; see SharedFiles.)
            string temporary = path + "." + Environment.ProcessId + ".tmp";
            StreamWriter writer = new StreamWriter(temporary, false, new UTF8Encoding(false));
            writer.Write(FileHeader + "\n");
            writer.Write("t_low\t" + Format.Exact(TLow) + "\n");
            writer.Write("t_high\t" + Format.Exact(THigh) + "\n");
            writer.Write("bias\t" + Format.Exact(Bias) + "\n");
            writer.Write("sublinear_tf\t" + (Featurizer.SublinearTf ? "1" : "0") + "\n");
            writer.Write("type_copies\t" + (Featurizer.TypeCopies ? "1" : "0") + "\n");
            writer.Write("meta\t" + MetaWeights.Length + "\n");
            for (int i = 0; i < MetaWeights.Length; i++)
            {
                writer.Write(MetadataFeatures.Names[i] + "\t" + Format.Exact(MetaWeights[i]) + "\n");
            }
            writer.Write("text\t" + Featurizer.Size + "\n");
            for (int j = 0; j < Featurizer.Size; j++)
            {
                writer.Write(Featurizer.Term(j) + "\t" + Format.Exact(Featurizer.Idf(j)) + "\t"
                    + Format.Exact(TextWeights[j]) + "\n");
            }
            writer.Close();
            SharedFiles.MoveWithRetry(temporary, path);   // replaces the old model
        }

        // Reads a model saved by Save. Refuses files from an older version, or ones whose flags
        // don't match the code, instead of using them wrongly.
        public static ScamModel Load(string path)
        {
            StreamReader reader = DataFiles.OpenReader(path);
            try
            {
                string header = DataFiles.StripBom(reader.ReadLine());
                if (header != null && header.StartsWith("SCAMMODEL ", StringComparison.Ordinal) && header != FileHeader)
                {
                    throw new IOException("The model was saved by an older version of ScamFilter. Retrain the model.");
                }
                if (header != FileHeader)
                {
                    throw new IOException(path + " is not a scam model file");
                }
                double tLow = ReadNumber(reader, "t_low");
                double tHigh = ReadNumber(reader, "t_high");
                double bias = ReadNumber(reader, "bias");
                bool sublinearTf = ReadNumber(reader, "sublinear_tf") != 0.0;
                bool typeCopies = ReadNumber(reader, "type_copies") != 0.0;

                // The flags in the file must match the flags in the code, in the same order.
                // Otherwise each weight would be applied to the wrong flag.
                int metaCount = (int) ReadNumber(reader, "meta");
                if (metaCount != MetadataFeatures.Count)
                {
                    throw new IOException("Model has " + metaCount + " metadata flags but the code has "
                        + MetadataFeatures.Count + ". Retrain the model.");
                }
                double[] metaWeights = new double[metaCount];
                for (int i = 0; i < metaCount; i++)
                {
                    string[] parts = reader.ReadLine().Split('\t');
                    if (parts[0] != MetadataFeatures.Names[i])
                    {
                        throw new IOException("Metadata flag " + i + " is '" + parts[0] + "' in the model but '"
                            + MetadataFeatures.Names[i] + "' in the code. Retrain the model.");
                    }
                    metaWeights[i] = Format.Parse(parts[1]);
                }

                int textCount = (int) ReadNumber(reader, "text");
                string[] terms = new string[textCount];
                double[] idf = new double[textCount];
                double[] weights = new double[textCount];
                for (int j = 0; j < textCount; j++)
                {
                    // Split on tabs only, which keeps the trailing space in n-grams like "c:ver " (end of a word)
                    string[] parts = reader.ReadLine().Split('\t');
                    terms[j] = parts[0];
                    idf[j] = Format.Parse(parts[1]);
                    weights[j] = Format.Parse(parts[2]);
                }

                ScamModel model = new ScamModel(new Featurizer(terms, idf, sublinearTf, typeCopies), metaWeights);
                model.TextWeights = weights;
                model.Bias = bias;
                model.TLow = tLow;
                model.THigh = tHigh;
                return model;
            }
            finally
            {
                reader.Close();   // runs whether loading worked or threw an error
            }
        }

        // Reads a "key<TAB>number" line and checks that the key is the expected one.
        private static double ReadNumber(StreamReader reader, string expectedKey)
        {
            string line = reader.ReadLine();
            if (line == null)
            {
                throw new IOException("Model file ended early (expected " + expectedKey + ")");
            }
            string[] parts = line.Split('\t');
            if (parts[0] != expectedKey || parts.Length < 2)
            {
                throw new IOException("Model file: expected '" + expectedKey + "' but found '" + line + "'");
            }
            return Format.Parse(parts[1]);
        }
    }

    /*
     * One input's share of the score: weight x value (see ScamModel.Explain).
     * Positive pushes toward scam, negative toward safe.
     */
    public class Reason
    {
        public readonly string Label;   // "A domain imitates a well-known brand", or word "verify"
        public readonly double Value;   // how much it added to z; NaN when a list made the call
        public readonly bool IsFlag;    // true for metadata flags, false for text features

        public Reason(string label, double value, bool isFlag)
        {
            Label = label;
            Value = value;
            IsFlag = isFlag;
        }

        // "+2.50  A domain imitates a well-known brand", or just the label when there's no number.
        public override string ToString()
        {
            if (double.IsNaN(Value))
            {
                return Label;
            }
            return Format.Signed(Value, 2) + "  " + Label;
        }
    }
}
