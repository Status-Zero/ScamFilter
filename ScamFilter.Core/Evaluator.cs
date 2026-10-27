using System;
using System.Collections.Generic;
using System.Linq;

namespace ScamFilter
{
    /*
     * The "final exam" report: how the model does on the test set, which it has never seen.
     * Run it only on test data. A score on data the model trained on is meaningless,
     * because the model could simply have memorized those messages.
     *
     * What's in the report, in order of importance:
     *
     *   BAND TABLE (a "confusion matrix"): true label down the side, the app's answer across:
     *                      SAFE  CAUTION  UNSAFE
     *       true scam        2       5      93      <- the 2 under SAFE is the WORST error:
     *       true legit     880      90      30         scams that sail through
     *                                         ^
     *                                         second worst: legit messages called UNSAFE,
     *                                         which is how users stop trusting the app
     *
     *   LOG LOSS: the average "how wrong" score from training (see LogisticTrainer). Lower is better.
     *
     *   AUC: pick one random scam and one random legit message. AUC is the chance the model
     *        gives the scam the higher score. 0.5 = a coin flip, 1.0 = perfect. It doesn't
     *        depend on the thresholds at all, so it measures pure ranking quality.
     *
     *   ACCURACY: the share of messages it got right, counting UNSAFE as "scam" and SAFE or
     *             CAUTION as "not scam". Easy to read, but easy to fool too: if 5% of messages
     *             are scams, a model that says "not scam" to everything is 95% accurate and
     *             useless. That's why the band table, recall, and AUC are reported with it.
     *
     *   BY SOURCE / BY CHANNEL: the same numbers split by dataset and by raw vs OCR, to catch
     *             the model doing much worse on one kind of message than another.
     */
    public static class Evaluator
    {
        // The headline numbers from a report.
        public class Result
        {
            public double Auc = double.NaN;               // area under the ROC curve: 1.0 perfect, 0.5 coin flip
            public double Accuracy = double.NaN;          // UNSAFE counted as "scam"
            public double Accuracy50 = double.NaN;        // score of 0.5 or more counted as "scam"
            public double TextAccuracy50 = double.NaN;    // the same, for text messages only
            public double EmailAccuracy50 = double.NaN;   // and for emails only
        }

        // Scores `records` (already turned into `examples`), prints the full report through `log`,
        // and returns the headline numbers. `prevalence` is the real-world scam rate used to
        // translate precision to everyday use (see ThresholdPicker).
        public static Result Report(string title, ScamModel model, List<MessageRecord> records,
                                    List<LogisticTrainer.Example> examples, double prevalence, Action<string> log)
        {
            Result result = new Result();
            log("");
            log("=== " + title + " ===");
            int n = examples.Count;
            if (n == 0)
            {
                log("No records.");
                return result;
            }

            // Score every test message.
            double[] p = new double[n];
            int[] y = new int[n];
            double loss = 0.0;
            for (int i = 0; i < n; i++)
            {
                LogisticTrainer.Example ex = examples[i];
                p[i] = ScamModel.Sigmoid(model.Logit(ex.X, ex.Flags));
                y[i] = ex.Y;
                loss += LogisticTrainer.LogLoss(p[i], ex.Y);
            }
            loss /= n;
            double auc = Auc(p, y);
            result.Auc = auc;

            // bands[true label, band], where band 0 = SAFE, 1 = CAUTION, 2 = UNSAFE
            int[,] bands = new int[2, 3];

            // Treating UNSAFE (p >= t_high) as "flagged":
            int tp = 0;   // true positive:  scam, flagged          (right)
            int fp = 0;   // false positive: legit, flagged         (wrong)
            int fn = 0;   // false negative: scam, not flagged      (wrong)
            int tn = 0;   // true negative:  legit, not flagged     (right)
            int right50 = 0;   // right answers when anything scoring 0.5+ counts as a scam

            // Per channel: [scams, scams not SAFE, legit, legit SAFE]. A plain List keeps first-seen order.
            List<string> channelNames = new List<string>();
            Dictionary<string, int[]> byChannel = new Dictionary<string, int[]>();
            List<string> missedScams = new List<string>();
            List<string> flaggedLegit = new List<string>();

            // Per source: [scams, scams not SAFE, legit, legit SAFE], first-seen order.
            List<string> sourceNames = new List<string>();
            Dictionary<string, int[]> bySource = new Dictionary<string, int[]>();

            // Per message type, index 0 = texts, 1 = emails:
            // [messages, right at 0.5, scams scored under 0.5 (missed), legit scored 0.5+ (flagged)]
            int[][] byType = new int[][] { new int[4], new int[4] };

            for (int i = 0; i < n; i++)
            {
                int[] t = byType[records[i].IsEmail() ? 1 : 0];
                t[0]++;
                if ((p[i] >= 0.5 ? 1 : 0) == y[i])
                {
                    right50++;
                    t[1]++;
                }
                else if (y[i] == 1)
                {
                    t[2]++;
                }
                else
                {
                    t[3]++;
                }
                string band = model.Band(p[i]);
                int b = band == ScamModel.Safe ? 0 : (band == ScamModel.Caution ? 1 : 2);
                bands[y[i], b]++;

                bool predictedScam = p[i] >= model.THigh;
                if (predictedScam && y[i] == 1)
                {
                    tp++;
                }
                if (predictedScam && y[i] == 0)
                {
                    fp++;
                }
                if (!predictedScam && y[i] == 1)
                {
                    fn++;
                }
                if (!predictedScam && y[i] == 0)
                {
                    tn++;
                }

                string source = records[i].Source.Length > 0 ? records[i].Source : "(no source)";
                int[] sc;
                if (!bySource.TryGetValue(source, out sc))
                {
                    sc = new int[4];
                    bySource[source] = sc;
                    sourceNames.Add(source);
                }
                if (y[i] == 1)
                {
                    sc[0]++;
                    if (b != 0)
                    {
                        sc[1]++;
                    }
                }
                else
                {
                    sc[2]++;
                    if (b == 0)
                    {
                        sc[3]++;
                    }
                }

                string channel = records[i].Channel;
                int[] c;
                if (!byChannel.TryGetValue(channel, out c))
                {
                    c = new int[4];
                    byChannel[channel] = c;
                    channelNames.Add(channel);
                }
                if (y[i] == 1)
                {
                    c[0]++;
                    if (b != 0)
                    {
                        c[1]++;
                    }
                }
                else
                {
                    c[2]++;
                    if (b == 0)
                    {
                        c[3]++;
                    }
                }

                // Keep the actual messages behind the two worst errors, so you can read them.
                if (y[i] == 1 && b == 0)
                {
                    missedScams.Add("p=" + Format.Fixed(p[i], 3) + "  " + records[i].Preview(70));
                }
                if (y[i] == 0 && b == 2)
                {
                    flaggedLegit.Add("p=" + Format.Fixed(p[i], 3) + "  " + records[i].Preview(70));
                }
            }

            int positives = bands[1, 0] + bands[1, 1] + bands[1, 2];
            int negatives = bands[0, 0] + bands[0, 1] + bands[0, 2];
            log(n + " records (" + positives + " scams, " + negatives + " not scams)");
            log("Log loss: " + Format.Fixed(loss, 4) + "    AUC: " + Format.Fixed(auc, 4));
            log("");
            log("                 SAFE  CAUTION  UNSAFE");
            log("  true scam     " + bands[1, 0].ToString().PadLeft(5) + "  " + bands[1, 1].ToString().PadLeft(7)
                + "  " + bands[1, 2].ToString().PadLeft(6));
            log("  true legit    " + bands[0, 0].ToString().PadLeft(5) + "  " + bands[0, 1].ToString().PadLeft(7)
                + "  " + bands[0, 2].ToString().PadLeft(6));
            log("");

            // Precision on THIS set, and adjusted to the real-world scam rate (see ThresholdPicker).
            double recall = positives == 0 ? double.NaN : tp / (double) positives;
            double rawPrecision = (tp + fp) == 0 ? double.NaN : tp / (double) (tp + fp);
            double fpr = negatives == 0 ? double.NaN : fp / (double) negatives;
            double adjusted = ThresholdPicker.AdjustedPrecision(recall, fpr, prevalence);
            result.Accuracy = (tp + tn) / (double) n;
            result.Accuracy50 = right50 / (double) n;
            log("Accuracy: " + Format.Percent(result.Accuracy, 2) + "%  (UNSAFE counted as scam; SAFE and CAUTION as not)");
            log("Accuracy at a 50% cut-off: " + Format.Percent(result.Accuracy50, 2) + "%");
            log("At t_high: TP " + tp + "  FP " + fp + "  FN " + fn + "  TN " + tn);
            log("  recall " + Format.Percent(recall, 1) + "%   precision " + Format.Percent(rawPrecision, 1)
                + "% on this set,  " + Format.Percent(adjusted, 1) + "% at a " + Format.Percent(prevalence, 0)
                + "% real-world scam rate");

            // Texts and emails are different problems (a 160-character text vs. a full email
            // with a sender, links, and HTML), so each gets its own score.
            log("");
            log("By message type (accuracy at a 50% cut-off):");
            string[] typeNames = { "texts", "emails" };
            for (int k = 0; k < 2; k++)
            {
                int[] t = byType[k];
                if (t[0] == 0)
                {
                    continue;
                }
                double accuracy = t[1] / (double) t[0];
                if (k == 0)
                {
                    result.TextAccuracy50 = accuracy;
                }
                else
                {
                    result.EmailAccuracy50 = accuracy;
                }
                int wrong = t[0] - t[1];
                log("  " + typeNames[k].PadRight(7) + t[0].ToString().PadLeft(6) + " messages  "
                    + Format.Percent(accuracy, 2).PadLeft(6) + "% right   (" + wrong + " wrong: "
                    + t[2] + " scams missed, " + t[3] + " legit flagged)");
            }

            if (sourceNames.Count > 1)
            {
                log("");
                log("By source (scams caught = not SAFE,  legit cleared = SAFE):");
                foreach (string name in sourceNames)
                {
                    int[] c = bySource[name];
                    log("  " + name.PadRight(16) + " scams caught " + (c[1] + "/" + c[0]).PadRight(10)
                        + " legit cleared " + c[3] + "/" + c[2]);
                }
            }

            log("");
            log("By channel (scams caught = not SAFE,  legit cleared = SAFE):");
            foreach (string name in channelNames)
            {
                int[] c = byChannel[name];
                log("  " + name.PadRight(8) + " scams caught " + c[1] + "/" + c[0] + "   legit cleared " + c[3] + "/" + c[2]);
            }

            PrintList("Scams that came out SAFE (worst error):", missedScams, log);
            PrintList("Legit messages that came out UNSAFE:", flaggedLegit, log);
            return result;
        }

        // Prints a heading and a list of example messages (or "none").
        private static void PrintList(string title, List<string> items, Action<string> log)
        {
            log("");
            log(title + (items.Count == 0 ? " none" : ""));
            for (int i = 0; i < items.Count && i < 10; i++)
            {
                log("  " + items[i]);
            }
        }

        /*
         * AUC = the chance a random scam scores higher than a random legit message.
         *
         * Comparing every scam with every legit message would work but is slow (P x N pairs).
         * The shortcut: sort everything by score and number the positions 1, 2, 3, ... ("ranks").
         * Add up the scams' ranks. If the scams all sat at the very bottom, that sum would be
         * 1 + 2 + ... + P = P(P+1)/2. Everything above that minimum counts how many legit
         * messages the scams beat. So:
         *
         *     AUC = (sum of scam ranks - P(P+1)/2) / (P * N)
         *
         * Messages with exactly the same score share the average of their ranks, which counts
         * a tie as half a win. (This is the Mann-Whitney U statistic.)
         */
        public static double Auc(double[] scores, int[] labels)
        {
            int n = scores.Length;
            List<int> order = Enumerable.Range(0, n).OrderBy(i => scores[i]).ToList();   // lowest score first
            double[] ranks = new double[n];
            int pos = 0;
            while (pos < n)
            {
                // Find the run of messages that all have this same score.
                int j = pos;
                while (j + 1 < n && scores[order[j + 1]] == scores[order[pos]])
                {
                    j++;
                }
                double averageRank = (pos + j) / 2.0 + 1.0;   // ranks start at 1, positions at 0
                for (int k = pos; k <= j; k++)
                {
                    ranks[order[k]] = averageRank;
                }
                pos = j + 1;
            }
            double sumPositiveRanks = 0.0;
            int positives = 0;
            for (int k = 0; k < n; k++)
            {
                if (labels[k] == 1)
                {
                    sumPositiveRanks += ranks[k];
                    positives++;
                }
            }
            int negatives = n - positives;
            if (positives == 0 || negatives == 0)
            {
                return double.NaN;   // need both kinds to compare
            }
            return (sumPositiveRanks - positives * (positives + 1) / 2.0) / ((double) positives * negatives);
        }
    }
}
