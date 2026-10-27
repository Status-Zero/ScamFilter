using System.Collections.Generic;

namespace ScamFilter
{
    /*
     * One link in a message, described for people (built by MetadataFeatures.DescribeLinks).
     * The app shows these as plain text that can't be clicked.
     *
     *   Target    where the link really goes (after unwrapping Safe Links and similar)
     *   ShownAs   the address the message displays instead, when that's a DIFFERENT site
     *             ("" when the link shows nothing misleading)
     *   Warnings  red flags about this link, in plain words
     *   Note      neutral information, like "unwrapped from Microsoft Safe Links"
     */
    public class LinkInfo
    {
        public string Target = "";                           // where it really goes
        public string ShownAs = "";                          // a different site it pretends to be, or ""
        public List<string> Warnings = new List<string>();   // red flags, in plain words
        public string Note = "";                             // neutral information, or ""

        // Does the link have any red flags?
        public bool IsSuspicious
        {
            get { return Warnings.Count > 0; }
        }

        // The link as it's listed in the AI viewer: its target, what it showed, and its warnings.
        public override string ToString()
        {
            string s = Target;
            if (ShownAs.Length > 0)
            {
                s += "  (shown as " + ShownAs + ")";
            }
            foreach (string w in Warnings)
            {
                s += "\n      ! " + w;
            }
            return s;
        }
    }
}
