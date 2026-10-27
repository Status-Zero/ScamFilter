using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace ScamFilter
{
    /*
     * Link and domain checks, done on the text of the link only.
     *
     * ============================================================================
     *  RULE #1: NEVER VISIT A LINK
     * ============================================================================
     * Scam links often contain a unique tracking code, like  usps-help.top/t?id=8f2a91.
     * If anything requests that address (even just to see where a bit.ly goes), the scammer's
     * server learns that THIS person's number is real and that they engage. Their number then
     * gets more scams. So everything here works on the string itself.
     *
     * ============================================================================
     *  VOCABULARY FOR THIS CLASS
     * ============================================================================
     *   URL                  https://login.paypal.com:443/signin?x=1
     *   host                 login.paypal.com          (the machine the link goes to)
     *   TLD                  com                        (the last part: top-level domain)
     *   registered domain    paypal.com                 (the part someone actually buys; whoever
     *                                                    owns it controls every host under it)
     *   subdomain            login                      (anything to the left of that)
     *
     * Scammers can't use paypal.com, so they register something that LOOKS like it:
     *   paypa1.com                     a character swap (1 for l)
     *   paypal-secure-login.com        the brand plus extra words
     *   paypal.com.secure-login.xyz    the brand as a SUBDOMAIN of a domain they own
     *
     * ============================================================================
     *  BRAND RULES (brands are listed in data/brands.txt)
     * ============================================================================
     *   - keywords with 6+ letters match anywhere in a domain   ("paypal" in "paypalsecure")
     *   - keywords with 5 or fewer letters must match a whole piece between dots or dashes,
     *     because short words hide inside other words: "ups" is in "groups", "chase" is in
     *     "purchase"
     *   - a brand's official domains and free-mail domains are never look-alikes, and neither
     *     is the brand's own name on a major country domain (amazon.de, google.co.uk)
     *
     * ============================================================================
     *  WRAPPED LINKS
     * ============================================================================
     * Some services rewrite every link in an email so they can scan it when it's clicked.
     * Microsoft 365's "Safe Links" turns  https://www.paypal.com  into
     *   https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.paypal.com&data=...
     * Judged as-is, EVERY link in a work or school email would look like it goes somewhere other
     * than it says. UnwrapRedirect() reads the original link back out of the wrapper (without
     * visiting anything), and every check runs on the original.
     */
    public static class UrlAnalyzer
    {
        // ------------------------------------------------------------------
        // Regular expressions (patterns for finding text)
        //   \s    any whitespace          [^...]  any character NOT in the brackets
        //   +     one or more             *       zero or more        ?   optional
        //   \b    a word boundary (where a word starts or ends)
        // IgnoreCase makes [a-z] match capital letters too.
        // ------------------------------------------------------------------

        private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        // Links that start with http:// or https://, up to the next space, quote, or bracket.
        public static readonly Regex SchemeUrl = new Regex(@"https?://[^\s<>""']+", Options);

        // Email addresses: name@domain.tld
        public static readonly Regex Email = new Regex(
            @"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,12}", Options);

        // Bare domains with no http:// in front, like "usps-help.top/track": one or more
        // "label." pieces, then 2-12 letters, then an optional /path.
        // Matches are double-checked against KnownTlds before counting as a link.
        public static readonly Regex BareDomain = new Regex(
            @"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,12}\b(?:/[^\s<>""']*)?", Options);

        // Four numbers separated by dots: 194.32.77.10
        private static readonly Regex Ipv4 = new Regex(@"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$", Options);

        // Only these TLDs count for bare domains. Without this check, "address.Please" (OCR
        // dropping a space after a period) would count as a link. Common two-letter English
        // words that are also country codes (it, so, to, is, in, ...) are left out on purpose.
        private static readonly HashSet<string> KnownTlds = new HashSet<string>(new string[] {
            "com", "net", "org", "info", "biz", "io", "co", "us", "gov", "edu", "mil", "me", "app", "dev",
            "xyz", "top", "click", "icu", "zip", "mov", "cyou", "sbs", "cfd", "buzz", "rest", "live", "site",
            "online", "shop", "store", "link", "ly", "gl", "at", "gd", "cc", "tk", "ml", "ga", "cf", "gq",
            "ru", "cn", "uk", "ca", "de", "fr", "au", "nz", "ie", "eu", "jp", "br", "mx", "ph", "ng", "pk",
            "tv", "ai", "ws", "gg", "vip", "club", "pro", "mobi", "support", "help", "services", "page",
            "life", "world", "today", "fun", "space", "website", "tech", "digital", "cash", "money", "bond",
            "lat", "win", "bid", "loan", "work", "email", "cloud", "pw", "su", "ms"
        });

        // TLDs that show up far more in scam links than in normal mail, mostly because they're
        // very cheap. A weak signal on its own, not proof.
        private static readonly HashSet<string> RiskyTlds = new HashSet<string>(new string[] {
            "top", "xyz", "click", "icu", "zip", "mov", "cyou", "sbs", "cfd", "buzz", "rest",
            "tk", "ml", "ga", "cf", "gq", "pw", "su", "bond", "lat", "win", "bid", "loan"
        });

        // Services that turn any link into a short one, hiding where it really goes.
        private static readonly HashSet<string> Shorteners = new HashSet<string>(new string[] {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
            "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "v.gd", "lnkd.in", "bl.ink"
        });

        // Anyone can make an address on these, so they're never "official" for a brand.
        private static readonly HashSet<string> FreeMail = new HashSet<string>(new string[] {
            "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
            "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com", "protonmail.com",
            "proton.me", "gmx.com", "gmx.net", "mail.com", "yandex.com", "zoho.com", "tutanota.com"
        });

        // In some countries the registered domain is three pieces: amazon.co.uk, not co.uk.
        private static readonly HashSet<string> SecondLevel = new HashSet<string>(new string[] {
            "co", "com", "org", "net", "gov", "ac", "edu", "ne", "or"
        });

        // Major country domains where big brands own their own name (amazon.de, google.co.uk).
        // Cheap or often-abused country domains (.cc, .tk, .co, ...) are deliberately NOT here.
        private static readonly HashSet<string> MajorCountryTlds = new HashSet<string>(new string[] {
            "uk", "ca", "de", "fr", "it", "es", "nl", "be", "ch", "at", "se", "no", "dk", "fi", "ie",
            "pl", "pt", "au", "nz", "jp", "kr", "in", "sg", "hk", "mx", "br", "ar", "za"
        });

        /*
         * Email services' click trackers. Newsletters send every link through these, so the real
         * destination can't be read from the address. Their links shouldn't count as "goes
         * somewhere other than it says": for legit newsletters that's every single link.
         * (Scammers use these services too, which is why the other checks still run.)
         */
        private static readonly HashSet<string> ClickTrackers = new HashSet<string>(new string[] {
            "sendgrid.net", "list-manage.com", "mcsv.net", "mailchi.mp", "hubspotlinks.com",
            "exct.net", "exacttarget.com", "rs6.net", "ccsend.com", "klclick.com", "klclick1.com",
            "klclick2.com", "klclick3.com", "sparkpostmail.com", "mandrillapp.com", "cmail19.com",
            "cmail20.com", "createsend1.com", "awstrack.me", "mjt.lu", "mlsend.com", "sendibt2.com",
            "sendibt3.com", "convertkit-mail.com", "convertkit-mail2.com", "substack.com"
        });

        // ------------------------------------------------------------------
        // Brand data, loaded from data/brands.txt the first time a brand check runs ("lazy
        // loading"). It's built completely, then swapped in as one object, so a thread that's
        // halfway through a check never sees it half-loaded or being unloaded.
        // ------------------------------------------------------------------

        private class BrandData
        {
            public List<string> Keywords = new List<string>();                                   // "paypal", "ups", ...
            public Dictionary<string, string> DisplayNames = new Dictionary<string, string>();   // "paypal" -> "PayPal"
            // Brand -> its official domains
            public Dictionary<string, HashSet<string>> Official = new Dictionary<string, HashSet<string>>();
            public HashSet<string> AllOfficial = new HashSet<string>();      // every official domain
            public HashSet<string> OfficialLabels = new HashSet<string>();   // "paypal" from paypal.com, ...
        }

        // Held while the brand data loads, so two threads don't load it twice.
        private static readonly object BrandLock = new object();
        private static volatile BrandData brandData = null;   // "volatile": every thread sees the latest value

        /*
         * Brand keywords that are also common first or last names. "Chase Miller" is a person,
         * not the bank, so these only count in a name or subject that also has a company-ish
         * word ("Chase Bank", "Norton Support").
         */
        private static readonly HashSet<string> NameLikeBrands = new HashSet<string>(new string[] {
            "chase", "norton"
        });

        // Words that show a name is a company's, not a person's (see NameLikeBrands).
        private static readonly HashSet<string> CompanyWords = new HashSet<string>(new string[] {
            "bank", "banking", "card", "cards", "credit", "support", "team", "service", "services",
            "security", "secure", "alert", "alerts", "account", "accounts", "billing", "customer",
            "help", "helpdesk", "notification", "notifications", "fraud", "online", "official",
            "department", "dept", "center", "centre", "noreply", "reply", "antivirus", "lifelock",
            "renewal", "subscription", "protection", "verification", "verify"
        });

        // ------------------------------------------------------------------
        // Finding links in text
        // ------------------------------------------------------------------

        /*
         * Every link in a piece of text.
         * "Pay at usps-help.top/x or email me@gmail.com" -> [usps-help.top/x]
         * (Email addresses are removed first so their domains don't count as links.)
         */
        public static List<string> ExtractUrls(string text)
        {
            List<string> urls = new List<string>();
            if (string.IsNullOrEmpty(text))
            {
                return urls;
            }
            // Invisible characters can split a link so it isn't recognized: "pay[zero-width space]pal.com"
            text = TextNormalizer.RemoveInvisible(text);

            // 1. Links with http(s)://
            foreach (Match m in SchemeUrl.Matches(text))
            {
                urls.Add(StripTrailingPunctuation(m.Value));
            }
            // 2. Blank those out, blank out email addresses, then look for bare domains.
            string rest = SchemeUrl.Replace(text, " ");
            rest = Email.Replace(rest, " ");
            foreach (Match b in BareDomain.Matches(rest))
            {
                string candidate = StripTrailingPunctuation(b.Value);
                if (HasKnownTld(candidate))
                {
                    urls.Add(candidate);
                }
            }
            return urls;
        }

        /*
         * Replaces links with " zurlz " and emails with " zemailz " (used by TextNormalizer).
         * The text model sees THAT there was a link, not which one. Link evidence comes from the
         * metadata flags instead, so the model can't just memorize a list of scam domains.
         */
        public static string ReplaceLinks(string text)
        {
            string s = SchemeUrl.Replace(text, " zurlz ");
            s = Email.Replace(s, " zemailz ");
            // Bare domains need the KnownTlds check, so they're replaced one at a time by hand.
            StringBuilder output = new StringBuilder(s.Length);
            int last = 0;
            foreach (Match b in BareDomain.Matches(s))
            {
                if (HasKnownTld(b.Value))
                {
                    output.Append(s, last, b.Index - last);   // the text before this match
                    output.Append(" zurlz ");
                    last = b.Index + b.Length;
                }
            }
            output.Append(s, last, s.Length - last);            // the text after the last match
            return output.ToString();
        }

        // "amazon.com." -> "amazon.com" (a sentence's period isn't part of the link)
        private static string StripTrailingPunctuation(string s)
        {
            int end = s.Length;
            while (end > 0 && ".,!?;:)]}'\"".IndexOf(s[end - 1]) >= 0)
            {
                end--;
            }
            return s.Substring(0, end);
        }

        // ------------------------------------------------------------------
        // Pulling a URL apart
        // ------------------------------------------------------------------

        // "https://user@sub.paypal.com:8080/x?y" -> "sub.paypal.com"
        public static string Host(string url)
        {
            if (url == null)
            {
                return "";
            }
            string s = Authority(url);
            int at = s.LastIndexOf('@');
            if (at >= 0)
            {
                s = s.Substring(at + 1);   // everything before an @ is NOT where the link goes
            }
            int colon = s.IndexOf(':');
            if (colon >= 0)
            {
                s = s.Substring(0, colon);  // drop a port number like :8080
            }
            while (s.EndsWith('.'))
            {
                s = s.Substring(0, s.Length - 1);
            }
            return s;
        }

        // The part between "scheme://" and the first / ? or #.  "https://a.com/x" -> "a.com"
        private static string Authority(string url)
        {
            string s = url.Trim().ToLowerInvariant();
            int scheme = s.IndexOf("://", StringComparison.Ordinal);
            if (scheme >= 0)
            {
                s = s.Substring(scheme + 3);
            }
            int end = s.Length;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '/' || c == '?' || c == '#' || c == '\\')
                {
                    end = i;
                    break;
                }
            }
            return s.Substring(0, end);
        }

        // The path part, lowercased: "https://a.com/V2/url?u=x" -> "/v2/url"
        private static string PathOf(string url)
        {
            string s = url.Trim();
            int scheme = s.IndexOf("://", StringComparison.Ordinal);
            int start = scheme >= 0 ? scheme + 3 : 0;
            int end = s.Length;
            int pathStart = -1;
            for (int i = start; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '?' || c == '#')
                {
                    end = i;
                    break;
                }
                if (c == '/' && pathStart < 0)
                {
                    pathStart = i;
                }
            }
            if (pathStart < 0 || pathStart >= end)
            {
                return "/";
            }
            return s.Substring(pathStart, end - pathStart).ToLowerInvariant();
        }

        /*
         * One value from a link's query string, decoded:
         *   QueryParam("https://x.com/?url=https%3A%2F%2Fa.com&v=1", "url") -> "https://a.com"
         * Returns null if the link has no such parameter.
         */
        private static string QueryParam(string url, string name)
        {
            int q = url.IndexOf('?');
            if (q < 0)
            {
                return null;
            }
            int hash = url.IndexOf('#', q);
            string query = hash >= 0 ? url.Substring(q + 1, hash - q - 1) : url.Substring(q + 1);
            foreach (string pair in query.Split('&'))
            {
                int eq = pair.IndexOf('=');
                string key = eq >= 0 ? pair.Substring(0, eq) : pair;
                if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
                {
                    string value = eq >= 0 ? pair.Substring(eq + 1) : "";
                    return Uri.UnescapeDataString(value.Replace("+", "%20"));
                }
            }
            return null;
        }

        /*
         * Reads the original link out of a link-protection or redirect wrapper. Links that
         * aren't wrapped come back unchanged. Wrappers inside wrappers are unwrapped too.
         *
         *   Microsoft 365 Safe Links   ...safelinks.protection.outlook.com/?url=<original>
         *   Google redirect            google.com/url?q=<original>
         *   Proofpoint                 urldefense.proofpoint.com/v2/url?u=<encoded original>
         *                              urldefense.com/v3/__<original>__;...
         *   Barracuda                  linkprotect.cudasvc.com/url?a=<original>
         *   Facebook                   l.facebook.com/l.php?u=<original>
         */
        public static string UnwrapRedirect(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return "";
            }
            string current = url.Trim();
            for (int depth = 0; depth < 3; depth++)
            {
                string inner = UnwrapOnce(current);
                if (inner == null || inner == current
                    || !inner.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
                current = inner.Trim();
            }
            return current;
        }

        // Unwraps one layer of a wrapped link (Safe Links, a click tracker, ...). Returns the same
        // URL if it isn't wrapped.
        private static string UnwrapOnce(string url)
        {
            string host = Host(url);
            string path = PathOf(url);
            if (host.EndsWith("safelinks.protection.outlook.com", StringComparison.Ordinal))
            {
                return QueryParam(url, "url");
            }
            if ((host == "google.com" || host == "www.google.com") && path == "/url")
            {
                string q = QueryParam(url, "q");
                return q != null ? q : QueryParam(url, "url");
            }
            if (host == "urldefense.proofpoint.com" && path.StartsWith("/v2/url", StringComparison.Ordinal))
            {
                // Proofpoint v2 writes "%" as "-" and "/" as "_", then the usual %XX codes
                string u = QueryParam(url, "u");
                return u == null ? null : Uri.UnescapeDataString(u.Replace('-', '%').Replace('_', '/'));
            }
            if (host == "urldefense.proofpoint.com" && path.StartsWith("/v1/url", StringComparison.Ordinal))
            {
                return QueryParam(url, "u");
            }
            if (host == "urldefense.com" && path.StartsWith("/v3/__", StringComparison.Ordinal))
            {
                int start = url.IndexOf("/v3/__", StringComparison.OrdinalIgnoreCase) + 6;
                int end = url.IndexOf("__;", start, StringComparison.Ordinal);
                return end > start ? url.Substring(start, end - start) : null;
            }
            if (host == "linkprotect.cudasvc.com" && path == "/url")
            {
                return QueryParam(url, "a");
            }
            if ((host == "l.facebook.com" || host == "lm.facebook.com") && path == "/l.php")
            {
                return QueryParam(url, "u");
            }
            return null;
        }

        /*
         * True for links like "http://paypal.com@evil.com/". Browsers treat everything before
         * the @ as a username, so this actually goes to evil.com while LOOKING like PayPal.
         */
        public static bool HasUserinfo(string url)
        {
            return url != null && Authority(url).IndexOf('@') >= 0;
        }

        /*
         * The part someone actually registers:
         *   "login.paypal.com"            -> "paypal.com"
         *   "shop.amazon.co.uk"           -> "amazon.co.uk"
         *   "paypal.com.secure-login.xyz" -> "secure-login.xyz"   (so that's who owns it!)
         * (An approximation; the full rules are a long list called the Public Suffix List.)
         */
        public static string RegisteredDomain(string host)
        {
            if (string.IsNullOrEmpty(host))
            {
                return "";
            }
            if (IsIp(host))
            {
                return host;
            }
            string[] labels = host.Split('.');
            int n = labels.Length;
            if (n <= 2)
            {
                return host;
            }
            string tld = labels[n - 1];
            string second = labels[n - 2];
            if (tld.Length == 2 && SecondLevel.Contains(second))
            {
                return labels[n - 3] + "." + second + "." + tld;   // like amazon.co.uk
            }
            return second + "." + tld;
        }

        // Is this host a raw IPv4 address like 194.32.77.10?
        public static bool IsIp(string host)
        {
            return Ipv4.IsMatch(host);
        }

        /*
         * Domains can contain non-English letters, which get written as "xn--..." ("punycode").
         * Scammers use letters that look identical to English ones, like swapping the "a" in
         * "paypal.com" for a Cyrillic letter that's drawn exactly the same. The address looks
         * right on screen but is a completely different domain.
         */
        public static bool IsPunycode(string host)
        {
            if (host.Contains("xn--"))
            {
                return true;
            }
            foreach (char c in host)
            {
                if (c > 127)   // any character outside plain ASCII
                {
                    return true;
                }
            }
            return false;
        }

        // Is it a link shortener like bit.ly (which hides where the link really goes)?
        public static bool IsShortener(string host)
        {
            return Shorteners.Contains(host) || Shorteners.Contains(RegisteredDomain(host));
        }

        // Is it an email marketing company's click-tracking domain?
        public static bool IsClickTracker(string host)
        {
            return ClickTrackers.Contains(RegisteredDomain(host));
        }

        // Does it end in a top-level domain that's common in scams (.top, .xyz, ...)?
        public static bool HasRiskyTld(string host)
        {
            return RiskyTlds.Contains(Tld(host));
        }

        // Does it end in a real top-level domain (.com, .org, .uk, ...)? Used to tell
        // "paypal.com" from "file.txt" in plain text.
        public static bool HasKnownTld(string urlOrDomain)
        {
            return KnownTlds.Contains(Tld(Host(urlOrDomain)));
        }

        // Is it a free email provider (gmail.com, outlook.com, ...) that anyone can sign up for?
        public static bool IsFreeMail(string domain)
        {
            return FreeMail.Contains(RegisteredDomain(domain));
        }

        // "login.paypal.com" -> "com"
        public static string Tld(string host)
        {
            int dot = host.LastIndexOf('.');
            if (dot < 0)
            {
                return "";
            }
            return host.Substring(dot + 1);
        }

        // ------------------------------------------------------------------
        // Brands
        // ------------------------------------------------------------------

        // The brand data, loading data/brands.txt the first time it's needed.
        private static BrandData Brands()
        {
            BrandData current = brandData;
            if (current != null)
            {
                return current;
            }
            lock (BrandLock)
            {
                if (brandData == null)
                {
                    brandData = LoadBrands();
                }
                return brandData;
            }
        }

        // Each line of brands.txt:  keyword|Display Name   domain1, domain2, ...
        private static BrandData LoadBrands()
        {
            BrandData data = new BrandData();
            Regex firstSpace = new Regex(@"\s+");
            foreach (string line in DataFiles.ReadList(Paths.DataFile("brands.txt")))
            {
                string[] parts = firstSpace.Split(line, 2);   // the name part, then the rest of the line
                if (parts.Length < 2)
                {
                    continue;
                }
                // "bankofamerica|Bank of America  bankofamerica.com" has spaces inside the display
                // name, so for "|" lines the domains start after the LAST run of 2+ spaces or a tab.
                string head = parts[0];
                string domainsText = parts[1];
                if (head.Contains('|'))
                {
                    Match split = Regex.Match(line, @"^(\S+\|.*?)(?:\t|\s{2,})(\S.*)$");
                    if (split.Success)
                    {
                        head = split.Groups[1].Value.Trim();
                        domainsText = split.Groups[2].Value;
                    }
                }
                string[] names = head.Split('|');
                string keyword = names[0].Trim().ToLowerInvariant();
                if (keyword.Length == 0)
                {
                    continue;
                }
                HashSet<string> domains = new HashSet<string>();
                foreach (string d in Regex.Split(domainsText, @"[,\s]+"))
                {
                    string domain = RegisteredDomain(d.Trim().ToLowerInvariant());
                    if (domain.Length > 0)
                    {
                        domains.Add(domain);
                        data.AllOfficial.Add(domain);
                        int dot = domain.IndexOf('.');
                        data.OfficialLabels.Add(dot > 0 ? domain.Substring(0, dot) : domain);
                    }
                }
                if (!data.Official.ContainsKey(keyword))
                {
                    data.Keywords.Add(keyword);
                    data.Official[keyword] = domains;
                }
                else
                {
                    data.Official[keyword].UnionWith(domains);
                }
                if (names.Length > 1 && names[1].Trim().Length > 0)
                {
                    data.DisplayNames[keyword] = names[1].Trim();
                }
            }
            return data;
        }

        // Frees the brand data. It reloads automatically the next time it's needed.
        public static void UnloadBrands()
        {
            lock (BrandLock)
            {
                brandData = null;
            }
        }

        // How to write a brand for people: "paypal" -> "PayPal" (from brands.txt), else "Paypal".
        public static string BrandDisplayName(string keyword)
        {
            BrandData b = Brands();
            string name;
            if (b.DisplayNames.TryGetValue(keyword, out name))
            {
                return name;
            }
            return keyword.Length == 0 ? keyword : char.ToUpperInvariant(keyword[0]) + keyword.Substring(1);
        }

        // Which brand (if any) a piece of text claims to be.  "PayPal Support" -> "paypal"
        public static string FindBrandMention(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return null;
            }
            BrandData b = Brands();
            string lower = TextNormalizer.RemoveInvisible(text).ToLowerInvariant();
            string[] tokens = Regex.Split(lower, "[^a-z0-9]+");     // "bank of america" -> [bank, of, america]
            string joined = Regex.Replace(lower, "[^a-z0-9]", "");   // "bank of america" -> "bankofamerica"
            foreach (string keyword in b.Keywords)
            {
                if (!MatchesKeyword(keyword, joined, tokens))
                {
                    continue;
                }
                if (NameLikeBrands.Contains(keyword) && !HasCompanyWord(tokens))
                {
                    continue;   // probably a person called Chase, not the bank
                }
                return keyword;
            }
            return null;
        }

        // Does the name contain a word like "bank", "support" or "billing"?
        private static bool HasCompanyWord(string[] tokens)
        {
            foreach (string token in tokens)
            {
                if (CompanyWords.Contains(token))
                {
                    return true;
                }
            }
            return false;
        }

        // Which brand (if any) this is an official domain of.  "email.paypal.com" -> "paypal"
        public static string OfficialBrandFor(string domain)
        {
            BrandData b = Brands();
            foreach (string keyword in b.Keywords)
            {
                if (IsOfficialFor(keyword, domain))
                {
                    return keyword;
                }
            }
            return null;
        }

        /*
         * Is this one of the brand's official domains?
         *   ("paypal", "service.paypal.com") -> true
         *   ("amazon", "amazon.de")          -> true   (the brand's own name on a major country domain)
         */
        public static bool IsOfficialFor(string brand, string domain)
        {
            BrandData b = Brands();
            HashSet<string> official;
            if (!b.Official.TryGetValue(brand, out official))
            {
                return false;
            }
            string reg = RegisteredDomain(domain);
            if (official.Contains(reg))
            {
                return true;
            }
            if (!MajorCountryTlds.Contains(Tld(reg)))
            {
                return false;
            }
            int dot = reg.IndexOf('.');
            string label = dot > 0 ? reg.Substring(0, dot) : reg;
            foreach (string o in official)
            {
                if (o.StartsWith(label + ".", StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        /*
         * Returns the brand a host is imitating, or null if it isn't imitating one.
         *
         *   "paypa1-secure.com"            -> "paypal"   (character trick, when allowed)
         *   "paypal.com.secure-login.xyz"  -> "paypal"   (brand hidden in the subdomain)
         *   "usps-redelivery.info"         -> "usps"     (brand plus extra words)
         *   "paypal.com", "amazon.de"      -> null       (official)
         *   "gmail.com"                    -> null       (free mail)
         *
         * allowConfusables = true also catches character tricks (paypa1, arnazon, netfIix) and
         * one-letter typos (paypall). Pass false for OCR'd text: OCR makes exactly these mistakes
         * on its own, so they can't be trusted there.
         */
        public static string LookalikeBrand(string host, bool allowConfusables)
        {
            if (string.IsNullOrEmpty(host) || IsIp(host))
            {
                return null;
            }
            BrandData b = Brands();
            string reg = RegisteredDomain(host);
            if (b.AllOfficial.Contains(reg) || FreeMail.Contains(reg))
            {
                return null;
            }
            int dot = reg.IndexOf('.');
            string regLabel = dot > 0 ? reg.Substring(0, dot) : reg;
            if (b.OfficialLabels.Contains(regLabel) && MajorCountryTlds.Contains(Tld(reg)))
            {
                return null;   // the brand's own name on a major country domain, like amazon.de
            }

            // Look at everything left of the TLD, subdomains included:
            //   "paypal.com.secure-login.xyz" -> region "paypal.com.secure-login"
            string sub = host.Length > reg.Length ? host.Substring(0, host.Length - reg.Length - 1) : "";
            string region = sub.Length > 0 ? sub + "." + regLabel : regLabel;

            // Two views of the region: glued together, and split into pieces.
            //   joined: "paypalcomsecurelogin"     tokens: [paypal, com, secure, login]
            string joined = region.Replace(".", "").Replace("-", "");
            string[] tokens = Regex.Split(region, @"[.\-]+");
            if (allowConfusables)
            {
                joined = NormalizeConfusables(joined);
                for (int i = 0; i < tokens.Length; i++)
                {
                    tokens[i] = NormalizeConfusables(tokens[i]);
                }
            }
            string labelForTypos = NormalizeConfusables(regLabel.Replace("-", ""));

            foreach (string keyword in b.Keywords)
            {
                // Normalize the keyword the same way, so both sides compare fairly.
                string k = allowConfusables ? NormalizeConfusables(keyword) : keyword;
                if (MatchesKeyword(k, joined, tokens))
                {
                    return keyword;
                }
                // One-letter typos, only for longer brand names (short ones collide with real words).
                if (allowConfusables && k.Length >= 6 && EditDistance(labelForTypos, k) <= 1)
                {
                    return keyword;
                }
            }
            return null;
        }

        // The two matching rules from the class comment: long keywords anywhere, short ones as whole pieces.
        private static bool MatchesKeyword(string keyword, string joined, string[] tokens)
        {
            if (keyword.Length >= 6)
            {
                return joined.Contains(keyword);
            }
            foreach (string token in tokens)
            {
                if (token == keyword)
                {
                    return true;
                }
            }
            return false;
        }

        /*
         * Maps characters people (and OCR) confuse onto one shape, so tricks compare equal:
         *   1 i | !  -> l        0 -> o        5 $ -> s        rn -> m        vv -> w
         *   "paypa1" -> "paypal",  "arnazon" -> "amazon",  "netfiix" and "netflix" -> "netfllx"
         * (Turning every i into l looks odd, but it's applied to BOTH sides of the comparison.)
         */
        public static string NormalizeConfusables(string s)
        {
            string t = s.Replace("rn", "m").Replace("vv", "w");
            StringBuilder sb = new StringBuilder(t.Length);
            foreach (char c in t)
            {
                if (c == '1' || c == 'i' || c == '|' || c == '!')
                {
                    sb.Append('l');
                }
                else if (c == '0')
                {
                    sb.Append('o');
                }
                else if (c == '5' || c == '$')
                {
                    sb.Append('s');
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        /*
         * Edit distance (Levenshtein distance): the fewest single-letter changes (insert, delete,
         * or replace a letter) that turn a into b.  "paypall" -> "paypal" = 1 (delete an l).
         *
         * How it works (dynamic programming): imagine a table where cell [i][j] holds the
         * distance between the first i letters of a and the first j letters of b. Each cell
         * comes from its neighbors:
         *   [i-1][j-1] + 0 or 1   (keep the letter if they match, otherwise replace it)
         *   [i-1][j]   + 1        (delete a letter)
         *   [i][j-1]   + 1        (insert a letter)
         * and takes the smallest. Each row only needs the row above it, so two arrays are enough.
         */
        public static int EditDistance(string a, string b)
        {
            int[] previous = new int[b.Length + 1];
            int[] current = new int[b.Length + 1];
            for (int j = 0; j <= b.Length; j++)
            {
                previous[j] = j;   // turning "" into j letters takes j inserts
            }
            for (int i = 1; i <= a.Length; i++)
            {
                current[0] = i;    // turning i letters into "" takes i deletes
                for (int j = 1; j <= b.Length; j++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    int best = previous[j - 1] + cost;   // keep or replace
                    if (previous[j] + 1 < best)
                    {
                        best = previous[j] + 1;          // delete
                    }
                    if (current[j - 1] + 1 < best)
                    {
                        best = current[j - 1] + 1;       // insert
                    }
                    current[j] = best;
                }
                int[] swap = previous;   // this row becomes "the row above" for the next one
                previous = current;
                current = swap;
            }
            return previous[b.Length];
        }
    }
}
