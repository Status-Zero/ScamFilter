using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ScamFilter
{
    // What a list entry is.
    public enum EntryKind { Phone, Email, Website }

    /*
     * One entry on the Blocked or Trusted list, already checked and written in its one standard
     * form ("canonical" form), so the same number typed three ways is the same entry.
     *
     *   typed                       Value                 Display              Key
     *   (404) 555-0142              14045550142           (404) 555-0142       phone:14045550142
     *   Mom@Gmail.com               mom@gmail.com         mom@gmail.com        email:mom@gmail.com
     *   https://pay.scam-site.top/x scam-site.top         scam-site.top        domain:scam-site.top
     *
     * Key is exactly what ScamDetector looks up, so a saved entry always matches the way the
     * detector reads it.
     */
    public class ListEntry
    {
        public EntryKind Kind;        // phone number, email address, or website
        public string Value = "";     // the standard form that's stored and compared
        public string Display = "";   // how it's shown in the app
        public string Label = "";     // an optional name, like "Mom" or "School"

        // What the detector looks up: "phone:...", "email:..." or "domain:...".
        public string Key
        {
            get
            {
                if (Kind == EntryKind.Phone)
                {
                    return "phone:" + Value;
                }
                return (Kind == EntryKind.Email ? "email:" : "domain:") + Value;
            }
        }

        // What kind of entry it is, in words for the list ("Phone number", ...)
        public string KindName
        {
            get
            {
                if (Kind == EntryKind.Phone)
                {
                    return Value.Length <= 6 ? "Business text number" : "Phone number";
                }
                if (Kind == EntryKind.Email)
                {
                    return "Email address";
                }
                return UrlAnalyzer.IsIp(Value) ? "Internet address (IP)" : "Website";
            }
        }
    }

    /*
     * The rules for what can and can't go on the Blocked and Trusted lists. They're written into
     * the program ("hard-coded") on purpose: people shouldn't have to know which entries are
     * dangerous, and a scammer coaching someone over the phone can't talk them past a rule.
     *
     * ============================================================================
     *  WHAT AN ENTRY CAN BE
     * ============================================================================
     *   PHONE NUMBER     10 digits (US), 11 starting with 1, or + and 8 to 15 digits
     *                    (international). Spaces, dashes, dots, and ( ) are fine.
     *                    A 5- or 6-digit number is a business text number ("short code").
     *   EMAIL ADDRESS    name@domain.tld
     *   WEBSITE          a domain like scam-site.top. A whole link can be pasted: only the site
     *                    is kept, and the main part of it ("pay.scam-site.top" -> "scam-site.top"),
     *                    because that's what the detector matches.
     *   Anything else is refused with a reason, never guessed at.
     *
     * ============================================================================
     *  WHAT'S NOT ALLOWED, AND WHY
     * ============================================================================
     *   On either list:
     *     - an entry already on the list, or already on the OTHER list (it can't be both)
     *     - more than MaxEntries entries
     *   On the BLOCKED list:
     *     - free email sites (gmail.com, outlook.com, ...): it would block everyone who uses them
     *     - a real company's own site or address (paypal.com): its real messages would come out
     *       as scams. The detector already checks whether a message really comes from PayPal.
     *     - link shorteners and email link trackers (bit.ly, sendgrid.net): real companies use
     *       them too, so blocking one blocks thousands of senders
     *     - your own email address
     *   On the TRUSTED list:
     *     - a whole free email site: it would trust every stranger with a Gmail address
     *     - a real company's site or address: scammers can send messages THROUGH a company's
     *       own systems (a fake PayPal invoice really comes from paypal.com), so those messages
     *       are always judged on what they say
     *     - anything that imitates a company (paypa1.com, paypal.support.team@gmail.com)
     *     - link shorteners, trackers, raw IP addresses, and look-alike-letter (punycode) sites
     */
    public static class ListRules
    {
        public const int MaxEntries = 500;       // the most entries one list can hold
        public const int MaxLabelLength = 40;    // the longest a label like "Mom" can be
        public const int MaxInputLength = 254;   // the longest an email address can be

        // The answer to "can this be added?"
        public class Result
        {
            public bool Ok;               // true if it can be added
            public ListEntry Entry;       // set when Ok
            public string Message = "";   // why it was refused, or a note about how it was saved
        }

        /*
         * Checks one typed entry.
         *   forBlocked    true for the Blocked list, false for Trusted
         *   sameList      what's on the list it's going onto
         *   otherList     what's on the other list
         *   ownAddresses  the user's own email addresses (their linked Outlook account)
         */
        public static Result Check(string input, string label, bool forBlocked,
                                   IEnumerable<ListEntry> sameList, IEnumerable<ListEntry> otherList,
                                   IEnumerable<string> ownAddresses)
        {
            Result result = Parse(input);
            if (!result.Ok)
            {
                return result;
            }
            ListEntry entry = result.Entry;

            string cleanLabel = (label ?? "").Trim();
            if (cleanLabel.Length > MaxLabelLength)
            {
                return Refuse("Keep the name to " + MaxLabelLength + " characters or fewer.");
            }
            foreach (char c in cleanLabel)
            {
                if (c == '#' || char.IsControl(c))
                {
                    return Refuse("Names can't contain # or line breaks.");
                }
            }
            entry.Label = cleanLabel;

            string why = forBlocked ? WhyNotBlocked(entry, ownAddresses) : WhyNotTrusted(entry);
            if (why != null)
            {
                return Refuse(why);
            }

            int count = 0;
            foreach (ListEntry existing in sameList)
            {
                count++;
                if (existing.Key == entry.Key)
                {
                    return Refuse(entry.Display + " is already on this list.");
                }
            }
            if (count >= MaxEntries)
            {
                return Refuse("This list is full (" + MaxEntries + " entries). Remove some old ones first.");
            }
            foreach (ListEntry existing in otherList)
            {
                if (existing.Key == entry.Key)
                {
                    return Refuse(entry.Display + " is on your " + (forBlocked ? "Trusted" : "Blocked")
                        + " list. Remove it from there first: something can't be both.");
                }
            }
            return result;
        }

        // ------------------------------------------------------------------
        // Reading what was typed
        // ------------------------------------------------------------------

        /*
         * Works out what was typed and writes it in standard form, without the list rules.
         * Also used to read saved list files back in.
         *   contains @                          -> an email address
         *   only digits and + ( ) - . spaces   -> a phone number
         *   anything else                       -> a website
         */
        public static Result Parse(string input)
        {
            string s = TextNormalizer.RemoveInvisible(input ?? "").Trim();
            if (s.Length == 0)
            {
                return Refuse("Type a phone number, an email address, or a website.");
            }
            if (s.Length > MaxInputLength)
            {
                return Refuse("That's too long to be a phone number, email address, or website.");
            }
            string lower = s.ToLowerInvariant();
            if (lower.StartsWith("mailto:", StringComparison.Ordinal))
            {
                lower = lower.Substring(7);
            }
            if (lower.StartsWith("tel:", StringComparison.Ordinal))
            {
                lower = lower.Substring(4);
            }
            if (lower.IndexOf('@') >= 0 && !lower.Contains("://"))
            {
                return ParseEmail(lower);
            }
            if (Regex.IsMatch(lower, @"^[+0-9\s().-]+$") && !Ipv4.IsMatch(lower))
            {
                return ParsePhone(lower);
            }
            return ParseWebsite(lower);
        }

        // An IPv4 address like 194.32.77.10 (each part 0 to 255).
        private static readonly Regex Ipv4 = new Regex(@"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$");
        // One part of a domain name: letters, digits, hyphens (not at either end), up to 63 long.
        private static readonly Regex DomainLabel = new Regex(@"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$");
        // The last part: 2 to 24 letters, or a punycode one (xn--...)
        private static readonly Regex TopLevel = new Regex(@"^([a-z]{2,24}|xn--[a-z0-9-]{1,59})$");
        // The part of an email address before the @, as the email standard allows it.
        private static readonly Regex EmailName = new Regex(@"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$");

        // Checks and cleans up an email address ("Mom@Gmail.com" -> "mom@gmail.com").
        private static Result ParseEmail(string s)
        {
            int at = s.LastIndexOf('@');
            string name = s.Substring(0, at);
            string domain = s.Substring(at + 1).TrimEnd('.');
            if (name.Length == 0 || name.Length > 64 || !EmailName.IsMatch(name) || s.IndexOf('@') != at)
            {
                return Refuse("That isn't a complete email address. It should look like name@example.com.");
            }
            string asciiDomain = ToAsciiDomain(domain);
            if (asciiDomain == null)
            {
                return Refuse("The part after the @ isn't a real domain. It should look like name@example.com.");
            }
            ListEntry entry = new ListEntry();
            entry.Kind = EntryKind.Email;
            entry.Value = name + "@" + asciiDomain;
            entry.Display = entry.Value;
            return Accept(entry, "");
        }

        // Checks and cleans up a phone number or short code ("(404) 555-0142" -> "14045550142").
        private static Result ParsePhone(string s)
        {
            bool plus = s.TrimStart().StartsWith("+", StringComparison.Ordinal);
            string digits = MetadataFeatures.DigitsOnly(s);
            ListEntry entry = new ListEntry();
            entry.Kind = EntryKind.Phone;
            if (s.IndexOf('+', 1) > 0)
            {
                return Refuse("A + can only go at the start of a phone number.");
            }
            if (!plus && (digits.Length == 5 || digits.Length == 6))
            {
                entry.Value = digits;   // a business text number, like 24273
                entry.Display = digits;
                return Accept(entry, "");
            }
            if (!plus && digits.Length == 7)
            {
                return Refuse("Include the area code: all 10 digits, like (404) 555-0142.");
            }
            string us = null;
            if (!plus && digits.Length == 10)
            {
                us = digits;
            }
            else if (digits.Length == 11 && digits[0] == '1')
            {
                us = digits.Substring(1);
            }
            if (us != null)
            {
                // US numbers: the area code and the next three digits can't start with 0 or 1.
                if (us[0] < '2' || us[3] < '2')
                {
                    return Refuse("That isn't a real US phone number. Check the digits.");
                }
                entry.Value = "1" + us;
                entry.Display = "(" + us.Substring(0, 3) + ") " + us.Substring(3, 3) + "-" + us.Substring(6);
                return Accept(entry, "");
            }
            if (plus && digits.Length >= 8 && digits.Length <= 15 && digits[0] != '0')
            {
                entry.Value = digits;
                entry.Display = "+" + digits;
                return Accept(entry, "");
            }
            if (plus && digits.Length > 0 && digits[0] == '1')
            {
                return Refuse("A +1 number has 10 digits after the 1.");
            }
            return Refuse("That doesn't look like a complete phone number. US numbers have 10 digits; "
                + "numbers from other countries start with + and the country code.");
        }

        // Checks a website or link and keeps just its domain ("https://pay.scam.top/x" -> "scam.top").
        private static Result ParseWebsite(string s)
        {
            string t = s;
            int scheme = t.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0)
            {
                t = t.Substring(scheme + 3);
            }
            // Keep only the site: drop the path, the ?query, a #part, and any login or port.
            int cut = t.IndexOfAny(new char[] { '/', '?', '#', '\\' });
            bool hadPath = cut >= 0 && cut < t.Length - 1;
            if (cut >= 0)
            {
                t = t.Substring(0, cut);
            }
            int at = t.LastIndexOf('@');
            if (at >= 0)
            {
                t = t.Substring(at + 1);
            }
            int colon = t.IndexOf(':');
            if (colon >= 0)
            {
                t = t.Substring(0, colon);
            }
            t = t.Trim().TrimEnd('.');
            if (t.StartsWith("www.", StringComparison.Ordinal))
            {
                t = t.Substring(4);
            }
            if (t.IndexOf(' ') >= 0 || t.Length == 0)
            {
                return Refuse("Type one phone number, email address, or website at a time.");
            }
            ListEntry entry = new ListEntry();
            entry.Kind = EntryKind.Website;
            if (Ipv4.IsMatch(t))
            {
                entry.Value = t;
                entry.Display = t;
                return Accept(entry, "");
            }
            string ascii = ToAsciiDomain(t);
            if (ascii == null)
            {
                return Refuse("That isn't a website, phone number, or email address. A website looks like example.com.");
            }
            entry.Value = UrlAnalyzer.RegisteredDomain(ascii);
            entry.Display = entry.Value;
            string note = "";
            if (entry.Value != ascii)
            {
                note = "Saved as " + entry.Value + ", which also covers " + ascii + ".";
            }
            else if (hadPath)
            {
                note = "Saved as the whole website " + entry.Value + ".";
            }
            return Accept(entry, note);
        }

        // A domain with non-English letters becomes its "xn--" form. null if it isn't a valid domain name.
        private static string ToAsciiDomain(string domain)
        {
            string ascii;
            try
            {
                ascii = new IdnMapping().GetAscii(domain).ToLowerInvariant();
            }
            catch (ArgumentException)
            {
                return null;
            }
            string[] labels = ascii.Split('.');
            if (labels.Length < 2 || ascii.Length > 253)
            {
                return null;
            }
            for (int i = 0; i < labels.Length; i++)
            {
                if (!DomainLabel.IsMatch(labels[i]))
                {
                    return null;
                }
            }
            return TopLevel.IsMatch(labels[labels.Length - 1]) ? ascii : null;
        }

        // ------------------------------------------------------------------
        // The rules
        // ------------------------------------------------------------------

        private static string WhyNotBlocked(ListEntry e, IEnumerable<string> ownAddresses)
        {
            if (e.Kind == EntryKind.Email)
            {
                foreach (string own in ownAddresses)
                {
                    if (own != null && own.Trim().ToLowerInvariant() == e.Value)
                    {
                        return "That's your own email address.";
                    }
                }
                string brand = OfficialBrandOf(MetadataFeatures.DomainOf(e.Value));
                if (brand != null)
                {
                    return e.Value + " is one of " + UrlAnalyzer.BrandDisplayName(brand) + "'s real addresses. Scammers fake it, "
                        + "but blocking it would mark " + UrlAnalyzer.BrandDisplayName(brand) + "'s real emails as scams. "
                        + "ScamFilter already checks whether an email really comes from them.";
                }
                return null;
            }
            if (e.Kind == EntryKind.Website)
            {
                if (UrlAnalyzer.IsFreeMail(e.Value))
                {
                    return "Blocking " + e.Value + " would block everyone with an address there. "
                        + "Block the person's full email address instead.";
                }
                string brand = OfficialBrandOf(e.Value);
                if (brand != null)
                {
                    return e.Value + " is " + UrlAnalyzer.BrandDisplayName(brand) + "'s real website. Blocking it would mark "
                        + "their real messages as scams. To block a fake, type the fake site's exact name.";
                }
                if (UrlAnalyzer.IsShortener(e.Value) || UrlAnalyzer.IsClickTracker(e.Value))
                {
                    return e.Value + " is used by thousands of real companies to shorten or track their links, "
                        + "so blocking it would block them all. ScamFilter looks at where those links lead instead.";
                }
            }
            return null;
        }

        // Why an entry may not go on the Trusted list, or null if it may (see the class comment).
        private static string WhyNotTrusted(ListEntry e)
        {
            if (e.Kind == EntryKind.Email)
            {
                string domain = MetadataFeatures.DomainOf(e.Value);
                string brand = OfficialBrandOf(domain);
                if (brand != null)
                {
                    return "Emails from " + UrlAnalyzer.BrandDisplayName(brand) + " can't be trusted automatically: scammers "
                        + "can send fake bills and invoices through " + UrlAnalyzer.BrandDisplayName(brand)
                        + "'s own systems. ScamFilter checks each of their emails on what it says.";
                }
                string imitated = UrlAnalyzer.LookalikeBrand(domain, true);
                if (imitated != null)
                {
                    return domain + " imitates " + UrlAnalyzer.BrandDisplayName(imitated) + "'s real website, so it can't be trusted.";
                }
                if (UrlAnalyzer.IsFreeMail(domain))
                {
                    string claimed = UrlAnalyzer.FindBrandMention(e.Value.Substring(0, e.Value.IndexOf('@')));
                    if (claimed != null)
                    {
                        return "This address pretends to be " + UrlAnalyzer.BrandDisplayName(claimed) + ", but it's a free "
                            + "email account anyone can make, so it can't be trusted.";
                    }
                }
                return null;
            }
            if (e.Kind == EntryKind.Website)
            {
                if (UrlAnalyzer.IsIp(e.Value))
                {
                    return "Internet addresses (numbers like " + e.Value + ") can't be trusted: they change hands.";
                }
                if (UrlAnalyzer.IsFreeMail(e.Value))
                {
                    return "Trusting " + e.Value + " would trust every stranger with an address there. "
                        + "Trust the person's full email address instead.";
                }
                string brand = OfficialBrandOf(e.Value);
                if (brand != null)
                {
                    return "All of " + e.Value + " can't be trusted: scammers can send fake bills and invoices through "
                        + UrlAnalyzer.BrandDisplayName(brand) + "'s own systems. ScamFilter checks each of their messages on what it says.";
                }
                if (UrlAnalyzer.IsShortener(e.Value) || UrlAnalyzer.IsClickTracker(e.Value))
                {
                    return e.Value + " shortens or tracks links for anyone, including scammers, so it can't be trusted.";
                }
                if (UrlAnalyzer.IsPunycode(e.Value))
                {
                    return e.Value + " is written with look-alike letters from other alphabets, a common disguise, so it can't be trusted.";
                }
                string imitated = UrlAnalyzer.LookalikeBrand(e.Value, true);
                if (imitated != null)
                {
                    return e.Value + " imitates " + UrlAnalyzer.BrandDisplayName(imitated) + "'s real website, so it can't be trusted.";
                }
            }
            return null;
        }

        // The brand whose official domain this is (from brands.txt), or null. Free email sites
        // never count, even when they belong to a brand (outlook.com is Microsoft's, but anyone
        // can have an address there).
        public static string OfficialBrandOf(string domain)
        {
            if (string.IsNullOrEmpty(domain) || UrlAnalyzer.IsFreeMail(UrlAnalyzer.RegisteredDomain(domain)))
            {
                return null;
            }
            return UrlAnalyzer.OfficialBrandFor(domain);
        }

        // A "no", with the reason in plain words.
        private static Result Refuse(string message)
        {
            Result r = new Result();
            r.Ok = false;
            r.Message = message;
            return r;
        }

        // A "yes", with the cleaned-up entry and an optional note about how it was saved.
        private static Result Accept(ListEntry entry, string note)
        {
            Result r = new Result();
            r.Ok = true;
            r.Entry = entry;
            r.Message = note;
            return r;
        }
    }
}
