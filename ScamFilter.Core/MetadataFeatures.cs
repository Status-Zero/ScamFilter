using System;
using System.Collections.Generic;
using System.Text;

namespace ScamFilter
{
    /*
     * The metadata half of the input: yes/no evidence about the sender, the links, and your
     * history with the sender. (The other half is the text itself; see Featurizer.)
     *
     * ============================================================================
     *  FLAGS
     * ============================================================================
     * Each flag is a number that's either 1 ("this evidence is present") or 0.
     *
     * Rule: every flag means "this specific piece of evidence is PRESENT".
     *       So 0 always means "absent OR unknown". That keeps unknown neutral automatically:
     *       a screenshot with no sender info just has fewer flags set, and missing information
     *       never counts as evidence that a message is safe.
     *
     * ============================================================================
     *  WEIGHTS
     * ============================================================================
     * Each flag has a weight that gets added to the score z when the flag is 1 (see ScamModel).
     * Weights are in "log-odds": +1 multiplies the odds of scam by about 2.7, and
     *
     *     +0.5 -> odds x1.6      +1.0 -> odds x2.7      +1.5 -> odds x4.5
     *     +2.0 -> odds x7.4      +2.5 -> odds x12       -2.0 -> odds /7.4
     *
     * These are HAND-SET for now, by judgment, and frozen during training. That's because
     * public datasets are mostly bare text with no sender or link metadata, so there's nothing
     * to learn them from. Once the app has collected real records with metadata (its "Mark as
     * scam" and "Mark as not a scam" buttons save them), set TrainingSettings.TrainMetaWeights =
     * true and training will learn them instead.
     *
     * To add a flag: add an index constant, an entry in Names, DefaultWeights, and Reasons
     * (all in the same position), and set it in Compute(). Then retrain.
     */
    public static class MetadataFeatures
    {
        // Your country's calling code without the +. Numbers starting with anything else count as international.
        public const string HomeCountryCode = "1";

        // Position of each flag in the arrays below. Each comment gives an example of when it fires.
        public const int IsEmail = 0;               // it's an email, not a text (context only)
        public const int DisplayNameMismatch = 1;   // "PayPal Support" <alerts@random-site.com>
        public const int FreemailBrandClaim = 2;    // a gmail.com address naming PayPal in its name or subject
        public const int ReplyToMismatch = 3;       // From @chase.com, but replies go to @protonmail.com
        public const int DmarcFail = 4;             // the claimed domain says "this email isn't from us"
        public const int SpfOrDkimFail = 5;         // weaker versions of the same sender check
        public const int HasUrl = 6;                // any link at all (context only)
        public const int HrefDisplayMismatch = 7;   // link text says paypal.com, link goes to paypa1-secure.com
        public const int LookalikeDomain = 8;       // paypa1.com, arnazon.com, usps-redelivery.info
        public const int UrlShortener = 9;          // bit.ly/..., which hides where the link goes
        public const int IpInUrl = 10;              // http://194.32.77.10/login instead of a domain name
        public const int PunycodeDomain = 11;       // xn--pypal-4ve.com, which displays with a look-alike letter
        public const int UserinfoInUrl = 12;        // http://paypal.com@evil.com goes to evil.com
        public const int RiskyTld = 13;             // .top, .xyz, .click, ... (cheap, popular with scammers)
        public const int DomainUnder30Days = 14;    // the linked domain was registered this month
        public const int SenderIsContact = 15;      // the sender is in your contacts
        public const int UserHasReplied = 16;       // you've written back to them before
        public const int InternationalNumber = 17;  // +44..., +63... when you're in the US
        public const int EmailSenderOnText = 18;    // a "text" that came from kdl9921@icloud.com
        public const int ShortCodeSender = 19;      // 5-6 digit sender like 24273 (registered businesses)

        // Internal names. These are written into the saved model file, so don't rename casually.
        public static readonly string[] Names = {
            "is_email",
            "display_name_mismatch",
            "freemail_brand_claim",
            "reply_to_mismatch",
            "dmarc_fail",
            "spf_or_dkim_fail",
            "has_url",
            "href_display_mismatch",
            "lookalike_domain",
            "url_shortener",
            "ip_in_url",
            "punycode_domain",
            "userinfo_in_url",
            "risky_tld",
            "domain_under_30_days",
            "sender_is_contact",
            "user_has_replied",
            "international_number",
            "email_sender_on_text",
            "short_code_sender"
        };

        // Hand-set starting weights, in log-odds (see the table in the class comment).
        private static readonly double[] DefaultWeightValues = {
            0.0,    // is_email               context only: 0 means it doesn't move the score
            1.5,    // display_name_mismatch
            1.0,    // freemail_brand_claim
            1.0,    // reply_to_mismatch
            2.0,    // dmarc_fail
            0.75,   // spf_or_dkim_fail
            0.0,    // has_url                context only (the text model sees "zurlz" anyway)
            2.5,    // href_display_mismatch  one of the strongest phishing signs there is
            2.5,    // lookalike_domain
            0.75,   // url_shortener          weak: legit businesses use shorteners too
            2.0,    // ip_in_url
            1.5,    // punycode_domain
            1.5,    // userinfo_in_url
            0.75,   // risky_tld              weak on its own
            1.5,    // domain_under_30_days
            -2.0,   // sender_is_contact      negative = evidence it's fine
            -1.0,   // user_has_replied
            0.5,    // international_number   weak: plenty of real people text from abroad
            1.0,    // email_sender_on_text
            -0.5    // short_code_sender      short codes have to be registered, so scammers rarely have one
        };

        // Plain-English explanations, shown to users as the reasons for a verdict.
        public static readonly string[] Reasons = {
            "It's an email",
            "The sender's name claims a brand the address doesn't belong to",
            "A free email account is claiming to be a company",
            "Replies would go to a different domain than the sender's",
            "The email failed DMARC (the sender's domain didn't vouch for it)",
            "The email failed SPF or DKIM checks",
            "Contains a link",
            "Link text shows one site but actually goes to another",
            "A domain imitates a well-known brand",
            "Uses a link shortener that hides the destination",
            "Link points to a raw IP address instead of a domain",
            "Domain uses look-alike international characters",
            "Link hides its real destination behind an '@'",
            "Link uses a top-level domain that's common in scams",
            "Linked domain is less than 30 days old",
            "Sender is in your contacts",
            "You've replied to this sender before",
            "Sent from an international number",
            "Text message sent from an email address",
            "Sent from a business short code"
        };

        // How many flags there are (20).
        public static int Count
        {
            get { return Names.Length; }
        }

        // A fresh copy of the default weights (a copy, so training can't change the originals).
        public static double[] DefaultWeights()
        {
            return (double[]) DefaultWeightValues.Clone();
        }

        /*
         * Every link in a record: the real targets (href), link text that looks like an address,
         * and anything that looks like a link in the message text itself. Wrapped links
         * (Microsoft Safe Links and similar) are unwrapped to the original first.
         */
        public static List<string> CollectLinks(MessageRecord r)
        {
            List<string> links = new List<string>();
            foreach (MessageRecord.UrlRef u in r.Urls)
            {
                if (u.Href.Length > 0)
                {
                    links.Add(UrlAnalyzer.UnwrapRedirect(u.Href));
                }
                if (LooksLikeUrl(u.Display))
                {
                    links.Add(u.Display);
                }
            }
            foreach (string link in UrlAnalyzer.ExtractUrls(r.FullText()))
            {
                links.Add(UrlAnalyzer.UnwrapRedirect(link));
            }
            return links;
        }

        /*
         * True when a link's visible text names one website but the link goes to another:
         *   shows "www.paypal.com", goes to "paypa1-secure.com"   -> true
         *   shows "www.nike.com",   goes to "click.e.nike.com"     -> false (same site)
         *   shows "www.nike.com",   goes to a newsletter tracker   -> false (destination unknown)
         */
        public static bool ShowsDifferentSite(MessageRecord.UrlRef u)
        {
            if (!LooksLikeUrl(u.Display) || u.Href.Length == 0)
            {
                return false;   // link text like "Click here" can't mismatch
            }
            string target = UrlAnalyzer.UnwrapRedirect(u.Href);
            string targetHost = UrlAnalyzer.Host(target);
            if (UrlAnalyzer.IsClickTracker(targetHost))
            {
                return false;
            }
            string shown = UrlAnalyzer.RegisteredDomain(UrlAnalyzer.Host(u.Display));
            string real = UrlAnalyzer.RegisteredDomain(targetHost);
            return shown.Length > 0 && real.Length > 0 && shown != real;
        }

        /*
         * The links in a message, described for people: where each really goes, what it pretends
         * to be, and what's wrong with it. The app shows these under "Links in this message".
         */
        public static List<LinkInfo> DescribeLinks(MessageRecord r)
        {
            bool allowConfusables = !r.IsOcr();
            List<LinkInfo> result = new List<LinkInfo>();
            HashSet<string> seen = new HashSet<string>();
            HashSet<string> linkTexts = new HashSet<string>();   // visible text of real links

            foreach (MessageRecord.UrlRef u in r.Urls)
            {
                if (u.Href.Length == 0)
                {
                    continue;
                }
                string target = UrlAnalyzer.UnwrapRedirect(u.Href);
                LinkInfo info = DescribeTarget(target, allowConfusables);
                if (ShowsDifferentSite(u))
                {
                    info.ShownAs = u.Display.Trim();
                    info.Warnings.Insert(0, "The message shows " + info.ShownAs + ", but this link goes to a different site");
                }
                if (target != u.Href.Trim() && info.Note.Length == 0)
                {
                    info.Note = "Unwrapped from a link-protection service (like Microsoft Safe Links)";
                }
                if (LooksLikeUrl(u.Display))
                {
                    linkTexts.Add(u.Display.Trim().ToLowerInvariant());
                }
                if (seen.Add(target.ToLowerInvariant()))
                {
                    result.Add(info);
                }
            }
            foreach (string link in UrlAnalyzer.ExtractUrls(r.FullText()))
            {
                // Skip text that's just the visible label of a link already listed above
                if (linkTexts.Contains(link.ToLowerInvariant()))
                {
                    continue;
                }
                string target = UrlAnalyzer.UnwrapRedirect(link);
                if (seen.Add(target.ToLowerInvariant()))
                {
                    LinkInfo info = DescribeTarget(target, allowConfusables);
                    if (target != link)
                    {
                        info.Note = "Unwrapped from a link-protection service (like Microsoft Safe Links)";
                    }
                    result.Add(info);
                }
            }
            return result;
        }

        // The warnings for one link destination.
        private static LinkInfo DescribeTarget(string target, bool allowConfusables)
        {
            LinkInfo info = new LinkInfo();
            info.Target = target;
            string host = UrlAnalyzer.Host(target);
            if (host.Length == 0)
            {
                return info;
            }
            if (UrlAnalyzer.IsIp(host))
            {
                info.Warnings.Add("Goes to a bare number address (an IP address) instead of a website name");
            }
            else
            {
                string brand = UrlAnalyzer.LookalikeBrand(host, allowConfusables);
                if (brand != null)
                {
                    info.Warnings.Add("Pretends to be " + UrlAnalyzer.BrandDisplayName(brand) + ", but isn't its real website");
                }
                if (UrlAnalyzer.IsShortener(host))
                {
                    info.Warnings.Add("A shortened link, which hides where it really goes");
                }
                if (UrlAnalyzer.IsPunycode(host))
                {
                    info.Warnings.Add("Uses look-alike letters from another alphabet");
                }
                if (UrlAnalyzer.HasRiskyTld(host))
                {
                    info.Warnings.Add("Ends in ." + UrlAnalyzer.Tld(host) + ", which is common in scam links");
                }
                if (UrlAnalyzer.IsClickTracker(host))
                {
                    info.Note = "Goes through an email service's click tracker, so the final website isn't visible";
                }
            }
            if (UrlAnalyzer.HasUserinfo(target))
            {
                info.Warnings.Add("The part before the @ is a disguise. It really goes to " + host);
            }
            return info;
        }

        // Computes every flag for one record. Returns an array of 0s and 1s, in Names order.
        public static double[] Compute(MessageRecord r)
        {
            double[] f = new double[Names.Length];

            // OCR can create look-alikes that aren't there (it reads "paypal" as "paypa1") and
            // erase ones that are. So for OCR'd text, the character-trick checks are switched off.
            bool allowConfusables = !r.IsOcr();
            string senderDomain = DomainOf(EmailAddress(r.Sender));

            if (r.IsEmail())
            {
                f[IsEmail] = 1.0;
            }

            // ---- Who is it from? (only possible when the sender is an email address) ----
            if (senderDomain.Length > 0)
            {
                // Does the display name claim a brand that this address doesn't belong to?
                string claimedInName = UrlAnalyzer.FindBrandMention(r.DisplayName);
                if (claimedInName != null && !UrlAnalyzer.IsOfficialFor(claimedInName, senderDomain))
                {
                    f[DisplayNameMismatch] = 1.0;
                }
                // A free address (gmail, outlook...) claiming a brand in its name or subject?
                if (UrlAnalyzer.IsFreeMail(senderDomain)
                    && (claimedInName != null || UrlAnalyzer.FindBrandMention(r.Subject) != null))
                {
                    f[FreemailBrandClaim] = 1.0;
                }
                // Would hitting "Reply" send your answer to a different organization?
                string replyDomain = DomainOf(EmailAddress(r.ReplyTo));
                if (replyDomain.Length > 0
                    && UrlAnalyzer.RegisteredDomain(replyDomain) != UrlAnalyzer.RegisteredDomain(senderDomain))
                {
                    f[ReplyToMismatch] = 1.0;
                }
                // Is the sender's own domain a look-alike? (service@paypa1-secure.com)
                if (UrlAnalyzer.LookalikeBrand(senderDomain, allowConfusables) != null)
                {
                    f[LookalikeDomain] = 1.0;
                }
            }

            // ---- Email authentication ----
            // When an email arrives, the receiving mail server checks whether the domain in "From"
            // really sent it (SPF, DKIM, DMARC) and writes the results into a header called
            // Authentication-Results. We just read those results; we never redo the checks.
            //   DMARC fail = the domain's own published policy says this email isn't from them.
            if (r.Dmarc == "fail")
            {
                f[DmarcFail] = 1.0;
            }
            if (r.Spf == "fail" || r.Spf == "softfail" || r.Dkim == "fail")
            {
                f[SpfOrDkimFail] = 1.0;
            }

            // ---- Links (analyzed as text only; never visited) ----
            List<string> links = CollectLinks(r);
            if (links.Count > 0)
            {
                f[HasUrl] = 1.0;
            }
            foreach (string link in links)
            {
                string host = UrlAnalyzer.Host(link);
                if (host.Length == 0)
                {
                    continue;
                }
                if (UrlAnalyzer.IsIp(host))
                {
                    f[IpInUrl] = 1.0;
                }
                else
                {
                    if (UrlAnalyzer.LookalikeBrand(host, allowConfusables) != null)
                    {
                        f[LookalikeDomain] = 1.0;
                    }
                    if (UrlAnalyzer.IsShortener(host))
                    {
                        f[UrlShortener] = 1.0;
                    }
                    if (UrlAnalyzer.IsPunycode(host))
                    {
                        f[PunycodeDomain] = 1.0;
                    }
                    if (UrlAnalyzer.HasRiskyTld(host))
                    {
                        f[RiskyTld] = 1.0;
                    }
                }
                if (UrlAnalyzer.HasUserinfo(link))
                {
                    f[UserinfoInUrl] = 1.0;
                }
            }
            // Link text that looks like one address while the real target is another.
            foreach (MessageRecord.UrlRef u in r.Urls)
            {
                if (ShowsDifferentSite(u))
                {
                    f[HrefDisplayMismatch] = 1.0;
                }
            }
            // Filled in by a domain-age lookup step if you add one; -1 (unknown) leaves it at 0.
            if (r.DomainAgeDays >= 0 && r.DomainAgeDays < 30)
            {
                f[DomainUnder30Days] = 1.0;
            }

            // ---- History with the sender ----
            // For a bool?, "== true" is true only when it's true; false and null (unknown) both fail.
            if (r.SenderIsContact == true)
            {
                f[SenderIsContact] = 1.0;
            }
            if (r.UserHasReplied == true)
            {
                f[UserHasReplied] = 1.0;
            }

            // ---- What kind of sender sent the text message? ----
            string sender = r.Sender.Trim();
            if (!r.IsEmail() && sender.Length > 0)
            {
                if (sender.IndexOf('@') >= 0)
                {
                    f[EmailSenderOnText] = 1.0;
                }
                else
                {
                    string digits = DigitsOnly(sender);
                    bool plus = sender.StartsWith('+');
                    if (plus && digits.Length > 0 && !digits.StartsWith(HomeCountryCode, StringComparison.Ordinal))
                    {
                        f[InternationalNumber] = 1.0;
                    }
                    // A short code is 5-6 digits with nothing else (no +, spaces, or dashes).
                    if (!plus && digits.Length >= 5 && digits.Length <= 6 && digits.Length == sender.Length)
                    {
                        f[ShortCodeSender] = 1.0;
                    }
                }
            }
            return f;
        }

        // ------------------------------------------------------------------
        // Small helpers (also used by ScamDetector)
        // ------------------------------------------------------------------

        // "PayPal <service@paypal.com>" -> "service@paypal.com". Returns "" if there's no email address.
        public static string EmailAddress(string s)
        {
            if (s == null)
            {
                return "";
            }
            string t = s.Trim();
            int open = t.IndexOf('<');
            int close = t.IndexOf('>');
            if (open >= 0 && close > open)
            {
                t = t.Substring(open + 1, close - open - 1).Trim();
            }
            if (t.IndexOf('@') <= 0)
            {
                return "";
            }
            return t.ToLowerInvariant();
        }

        // "service@paypal.com" -> "paypal.com"
        public static string DomainOf(string emailAddress)
        {
            int at = emailAddress.LastIndexOf('@');
            if (at < 0)
            {
                return "";
            }
            return emailAddress.Substring(at + 1);
        }

        // "+1 (404) 555-0142" -> "14045550142"
        public static string DigitsOnly(string s)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in s)
            {
                if (c >= '0' && c <= '9')
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        // "(404) 555-0142" and "+1 404 555 0142" both become "14045550142", so they compare equal.
        public static string NormalizePhone(string s)
        {
            string digits = DigitsOnly(s);
            if (digits.Length == 10 && HomeCountryCode == "1")
            {
                return "1" + digits;
            }
            return digits;
        }

        // True for link text like "www.paypal.com/login" or "https://...", false for "Click here".
        private static bool LooksLikeUrl(string display)
        {
            string d = display.Trim();
            if (d.Length == 0 || d.IndexOf(' ') >= 0)
            {
                return false;
            }
            if (d.ToLowerInvariant().StartsWith("http", StringComparison.Ordinal))
            {
                return true;
            }
            return d.IndexOf('.') > 0 && UrlAnalyzer.HasKnownTld(d);
        }
    }
}
