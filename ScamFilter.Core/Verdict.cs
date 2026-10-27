using System.Collections.Generic;
using System.Text;

namespace ScamFilter
{
    /*
     * The detector's answer for one message: the band, the model's probability (if the model
     * ran), what made the call, the reasons to show the user, and every link found, described
     * (the app shows links as plain text, never clickable).
     */
    public class Verdict
    {
        public readonly string Band;          // SAFE, CAUTION, or UNSAFE
        public readonly double Probability;   // the model's P(scam), or -1 when the model didn't run
        public readonly string DecidedBy;     // "blocklist", "whitelist", or "model"
        public readonly List<Reason> Reasons; // e.g. +2.50  A domain imitates a well-known brand
        public readonly List<LinkInfo> Links; // every link in the message, described

        public Verdict(string band, double probability, string decidedBy, List<Reason> reasons, List<LinkInfo> links)
        {
            Band = band;
            Probability = probability;
            DecidedBy = decidedBy;
            Reasons = reasons;
            Links = links;
        }

        // A verdict made by the blocklist or whitelist, before the model runs (so no probability).
        public static Verdict Decided(string band, string decidedBy, string reason, List<LinkInfo> links)
        {
            List<Reason> reasons = new List<Reason>();
            reasons.Add(new Reason(reason, double.NaN, true));
            return new Verdict(band, -1.0, decidedBy, reasons, links);
        }

        /*
         * Readable form, e.g.
         *   UNSAFE  (P(scam) = 0.948)  [decided by model]
         *      +2.50  A domain imitates a well-known brand
         * The number before each reason is how much it added to the score z (see ScamModel).
         */
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Band);
            if (Probability >= 0.0)
            {
                sb.Append("  (P(scam) = " + Format.Fixed(Probability, 3) + ")");
            }
            sb.Append("  [decided by ").Append(DecidedBy).Append(']');
            foreach (Reason reason in Reasons)
            {
                sb.Append("\n   ").Append(reason.ToString());
            }
            return sb.ToString();
        }
    }
}
