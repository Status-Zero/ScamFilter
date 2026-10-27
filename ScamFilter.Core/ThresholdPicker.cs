using System;
using System.Collections.Generic;
using System.Linq;

namespace ScamFilter
{
    /*
     * Picks the two cut-off points that split p into SAFE / CAUTION / UNSAFE.
     *
     * The model outputs a number p between 0 and 1. Where to draw the lines is a separate
     * decision, made here using the validation set (messages the model didn't train on).
     *
     * ============================================================================
     *  THE TWO MEASURES: PRECISION AND RECALL
     * ============================================================================
     * Pick a threshold t and call everything with p >= t "scam". Then:
     *
     *   RECALL     = of all the real scams, what fraction did we flag?
     *                (also called TPR, the "true positive rate")
     *   PRECISION  = of everything we flagged, what fraction really was a scam?
     *
     * They pull against each other. Lower t flags more: recall goes up (fewer scams missed)
     * but precision goes down (more legit messages wrongly flagged). Raise t and the
     * opposite happens. So:
     *
     *   t_high = the LOWEST threshold where precision >= precisionTarget
     *            Plain meaning: "when the app says UNSAFE, it's right (say) 95% of the time."
     *   t_low  = the HIGHEST threshold where recall >= recallTarget
     *            Plain meaning: "only (say) 2% of scams slip under t_low and come out SAFE."
     *
     *   Between them is CAUTION: the region where the model can't be confident either way.
     *
     * ============================================================================
     *  THE TRAP: PRECISION DEPENDS ON HOW COMMON SCAMS ARE
     * ============================================================================
     * Precision isn't just about the model; it depends on how many scams there are to begin
     * with. Say the model flags 95% of scams (TPR = 0.95) and wrongly flags 2% of legit
     * messages (FPR = 0.02, the "false positive rate"). Out of 1000 messages:
     *
     *   validation set, 50% scams:  flags 475 scams + 10 legit  -> precision 475/485 = 0.98
     *   real inbox,      5% scams:  flags  48 scams + 19 legit  -> precision  48/67  = 0.71
     *
     * Same model, same threshold, very different precision. The validation set is usually
     * far scam-heavier than a real inbox, so precision is computed for the REAL-WORLD scam
     * rate pi instead of the validation set's:
     *
     *     precision = (TPR * pi) / (TPR * pi + FPR * (1 - pi))
     *
     *     TPR * pi        = the share of all messages that are scams AND get flagged
     *     FPR * (1 - pi)  = the share of all messages that are legit AND get flagged
     *
     * Recall doesn't have this problem: it only ever looks at scams.
     */
    public static class ThresholdPicker
    {
        // The chosen thresholds plus the numbers behind them.
        public class Result
        {
            public double TLow = 0.3;                            // defaults, used if picking isn't possible
            public double THigh = 0.7;                           // UNSAFE from here up
            public double PrecisionAtHigh = double.NaN;          // adjusted for the real-world scam rate
            public double RecallAtHigh = double.NaN;             // share of scams that reach UNSAFE
            public double RecallAtLow = double.NaN;              // share of scams that are not SAFE
            public double CautionRateOnLegit = double.NaN;       // fraction of legit messages landing in CAUTION
            public List<string> Warnings = new List<string>();   // problems found while picking, printed in the report

            // Prints the chosen thresholds and what they mean, for the training report.
            public void Print(double precisionTarget, double recallTarget, double prevalence, Action<string> log)
            {
                log("  t_high = " + Format.Fixed(THigh, 4) + "   (precision " + Format.Percent(PrecisionAtHigh, 1)
                    + "% at a " + Format.Percent(prevalence, 0) + "% scam rate, target " + Format.Percent(precisionTarget, 0)
                    + "%; recall " + Format.Percent(RecallAtHigh, 1) + "%)");
                log("  t_low  = " + Format.Fixed(TLow, 4) + "   (recall " + Format.Percent(RecallAtLow, 1)
                    + "%, target " + Format.Percent(recallTarget, 0) + "%)");
                // If this is high, users get "Caution" on lots of normal messages and learn to ignore it.
                log("  " + Format.Percent(CautionRateOnLegit, 1) + "% of legit validation messages land in CAUTION");
                foreach (string w in Warnings)
                {
                    log("  WARNING: " + w);
                }
            }
        }

        // precision = (TPR * pi) / (TPR * pi + FPR * (1 - pi))   (see the class comment)
        public static double AdjustedPrecision(double tpr, double fpr, double prevalence)
        {
            double flaggedScams = tpr * prevalence;
            double flaggedLegit = fpr * (1.0 - prevalence);
            if (flaggedScams + flaggedLegit == 0.0)
            {
                return 0.0;   // nothing flagged at all
            }
            return flaggedScams / (flaggedScams + flaggedLegit);
        }

        /*
         * Tries every possible threshold and picks t_low and t_high by the rules above.
         *
         * scores[i] = the model's p for validation message i;  labels[i] = its true label.
         */
        public static Result Pick(double[] scores, int[] labels, double precisionTarget,
                                  double recallTarget, double prevalence)
        {
            Result result = new Result();
            int n = scores.Length;
            int positives = 0;   // scams
            for (int i = 0; i < n; i++)
            {
                positives += labels[i];
            }
            int negatives = n - positives;   // legit
            if (positives == 0 || negatives == 0)
            {
                result.Warnings.Add("validation set needs both scams and non-scams; using default thresholds 0.3 / 0.7");
                return result;
            }
            if (positives < 50 || negatives < 200)
            {
                result.Warnings.Add("validation set is small (" + positives + " scams, " + negatives
                    + " non-scams). Thresholds stay noisy until you have ~50+ scams and ~200+ non-scams there.");
            }

            // Sort the messages by score, highest first.
            List<int> order = Enumerable.Range(0, n).OrderByDescending(i => scores[i]).ToList();

            // Sweep the threshold DOWN through every distinct score. At each step, everything
            // scored at or above the threshold counts as flagged:
            //   tp = scams flagged so far ("true positives")
            //   fp = legit messages flagged so far ("false positives")
            int tp = 0;
            int fp = 0;
            bool foundHigh = false;
            bool foundLow = false;
            double bestPrecision = -1.0;     // fallback if the precision target is never reached
            double bestPrecisionT = 1.0;
            double bestPrecisionRecall = 0.0;

            int pos = 0;
            while (pos < n)
            {
                double t = scores[order[pos]];
                // Include every message with exactly this score before measuring.
                while (pos < n && scores[order[pos]] == t)
                {
                    if (labels[order[pos]] == 1)
                    {
                        tp++;
                    }
                    else
                    {
                        fp++;
                    }
                    pos++;
                }
                double tpr = tp / (double) positives;   // recall
                double fpr = fp / (double) negatives;
                double precision = AdjustedPrecision(tpr, fpr, prevalence);

                if (precision >= precisionTarget)
                {
                    // Keeps overwriting as the sweep goes lower, so it ends on the LOWEST qualifying t.
                    result.THigh = t;
                    result.PrecisionAtHigh = precision;
                    result.RecallAtHigh = tpr;
                    foundHigh = true;
                }
                if (precision >= bestPrecision)
                {
                    bestPrecision = precision;
                    bestPrecisionT = t;
                    bestPrecisionRecall = tpr;
                }
                if (!foundLow && tpr >= recallTarget)
                {
                    // The first (= highest) threshold where recall reaches the target.
                    result.TLow = t;
                    result.RecallAtLow = tpr;
                    foundLow = true;
                }
            }

            if (!foundHigh)
            {
                result.THigh = bestPrecisionT;
                result.PrecisionAtHigh = bestPrecision;
                result.RecallAtHigh = bestPrecisionRecall;
                result.Warnings.Add("no threshold reached " + Format.Percent(precisionTarget, 0) + "% precision at a "
                    + Format.Percent(prevalence, 0) + "% scam rate; using the best one (" + Format.Percent(bestPrecision, 1) + "%)");
            }
            if (result.TLow > result.THigh)
            {
                result.TLow = result.THigh;
                result.Warnings.Add("CAUTION band is empty: the recall target is already met at t_high");
            }

            // How much of normal traffic would get a CAUTION label?
            int legitInCaution = 0;
            for (int k = 0; k < n; k++)
            {
                if (labels[k] == 0 && scores[k] >= result.TLow && scores[k] < result.THigh)
                {
                    legitInCaution++;
                }
            }
            result.CautionRateOnLegit = legitInCaution / (double) negatives;
            return result;
        }
    }
}
