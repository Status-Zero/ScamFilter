using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using MimeKit;

namespace ScamFilter
{
    /*
     * Turns a saved email file (.eml) into a MessageRecord. Nothing AI here: this is the
     * "email connector", one of the input channels that all end up as the same record format.
     * (MsgImporter does the same for Outlook's .msg files, and reuses the helpers below.)
     *
     * You get an .eml by dragging an email out of new Outlook or Thunderbird, or with
     * "Download message" / "Show original" in Gmail and Outlook on the web.
     *
     * MimeKit (a library) reads the email format itself. An email file is a stack of headers
     * (From, Subject, ...) followed by one or more "parts": plain text, HTML, images,
     * attachments, sometimes nested inside each other.
     *
     * What gets pulled out:
     *   - From (address and display name), Reply-To, Subject
     *   - the visible text, preferring the HTML version because only HTML links carry their
     *     real destination (href) separately from the text you see
     *   - every link as (what it says, where it really goes)
     *   - SPF / DKIM / DMARC results from the Authentication-Results header
     *   - image attachments, so the app can OCR any text hidden in pictures
     */
    public static class EmlImporter
    {
        // What reading an email gives: the record for the detector, plus its pictures.
        public class Result
        {
            public MessageRecord Record;                       // the email, as a record the detector can check
            public List<byte[]> Images = new List<byte[]>();   // raw image files, for OCR
        }

        // At most this many pictures are kept per email (OCR is slow, and scams rarely need more).
        public const int MaxImages = 5;

        // Reads an .eml file from disk.
        public static Result Load(string path)
        {
            return FromMessage(MimeMessage.Load(path));
        }

        // Reads an email from a stream (an email dragged out of Outlook arrives this way).
        public static Result Load(Stream stream)
        {
            return FromMessage(MimeMessage.Load(stream));
        }

        // Also used by the dataset importer (ScamFilter.Trainer), which reads whole mailboxes.
        public static Result FromMessage(MimeMessage message)
        {
            Result result = new Result();
            MessageRecord r = new MessageRecord();
            r.Type = "email";
            r.Channel = "raw";

            foreach (MailboxAddress from in message.From.Mailboxes)
            {
                r.Sender = from.Address == null ? "" : from.Address;
                r.DisplayName = from.Name == null ? "" : from.Name;
                break;   // only the first sender matters
            }
            foreach (MailboxAddress reply in message.ReplyTo.Mailboxes)
            {
                r.ReplyTo = reply.Address == null ? "" : reply.Address;
                break;
            }
            r.Subject = message.Subject == null ? "" : message.Subject;

            if (message.HtmlBody != null)
            {
                r.BodyText = HtmlToText(message.HtmlBody, r.Urls);
            }
            else if (message.TextBody != null)
            {
                r.BodyText = message.TextBody;
            }

            ReadAuthenticationResults(message.Headers, r);

            foreach (MimeEntity entity in message.BodyParts)
            {
                MimePart part = entity as MimePart;
                if (part != null && part.ContentType.MediaType == "image" && result.Images.Count < MaxImages)
                {
                    MemoryStream bytes = new MemoryStream();
                    part.Content.DecodeTo(bytes);
                    result.Images.Add(bytes.ToArray());
                    bytes.Close();
                }
            }
            result.Record = r;
            return result;
        }

        /*
         * Fills in what a raw header block can add to a record (used for .msg files, whose
         * headers come as one big piece of text): the sender checks, plus From and Reply-To
         * when the record doesn't have them yet.
         */
        public static void ApplyHeaderText(string rawHeaders, MessageRecord r)
        {
            if (string.IsNullOrWhiteSpace(rawHeaders))
            {
                return;
            }
            HeaderList headers;
            MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(rawHeaders.TrimEnd() + "\r\n\r\n"));
            try
            {
                headers = HeaderList.Load(stream);
            }
            catch (FormatException)
            {
                return;   // unreadable headers just add nothing
            }
            finally
            {
                stream.Close();
            }
            ReadAuthenticationResults(headers, r);

            if (r.Sender.IndexOf('@') < 0)
            {
                InternetAddressList from;
                if (InternetAddressList.TryParse(headers[HeaderId.From] ?? "", out from))
                {
                    foreach (MailboxAddress m in from.Mailboxes)
                    {
                        r.Sender = m.Address ?? "";
                        if (r.DisplayName.Length == 0)
                        {
                            r.DisplayName = m.Name ?? "";
                        }
                        break;
                    }
                }
            }
            if (r.ReplyTo.Length == 0)
            {
                InternetAddressList replyTo;
                if (InternetAddressList.TryParse(headers[HeaderId.ReplyTo] ?? "", out replyTo))
                {
                    foreach (MailboxAddress m in replyTo.Mailboxes)
                    {
                        r.ReplyTo = m.Address ?? "";
                        break;
                    }
                }
            }
        }

        /*
         * The receiving mail server records its SPF / DKIM / DMARC checks in a header like:
         *   Authentication-Results: mx.google.com; spf=pass ...; dkim=pass ...; dmarc=fail ...
         *
         * Only the TOP one can be trusted. Each server adds its header above the existing ones,
         * so the top one was written by your own mail provider. Anything lower could have been
         * typed in by the sender to fake a "pass".
         */
        private static void ReadAuthenticationResults(HeaderList headers, MessageRecord r)
        {
            foreach (Header header in headers)
            {
                if (header.Id == HeaderId.AuthenticationResults)
                {
                    string value = header.Value.ToLowerInvariant();
                    r.Spf = FindResult(value, "spf");
                    r.Dkim = FindResult(value, "dkim");
                    r.Dmarc = FindResult(value, "dmarc");
                    return;   // the topmost one only
                }
            }
        }

        // FindResult("spf=pass smtp.mailfrom=...", "spf") -> "pass"
        private static string FindResult(string header, string method)
        {
            Match m = Regex.Match(header, @"\b" + method + @"\s*=\s*([a-z]+)");
            return m.Success ? m.Groups[1].Value : "";
        }

        /*
         * HTML -> visible text, collecting links along the way.
         *   <a href="http://paypa1.com/x">www.paypal.com</a>
         *     becomes the visible text "www.paypal.com"
         *     and the link (display: "www.paypal.com", href: "http://paypa1.com/x")
         * That pair is exactly what the "link text shows one site but goes to another" flag needs.
         *
         * Also used for HTML pasted from the clipboard (copying from Outlook or Gmail in a browser
         * puts HTML on the clipboard, real link targets included).
         */
        public static string HtmlToText(string html, List<MessageRecord.UrlRef> links)
        {
            RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.Singleline;
            // Invisible content: styles, scripts, and HTML comments (including Outlook's
            // <!--[if mso]> ... <![endif]--> blocks)
            string s = Regex.Replace(html, @"<(style|script|head|title)\b.*?</\1>", " ", options);
            s = Regex.Replace(s, @"<!--.*?-->", " ", options);
            s = RemoveHiddenElements(s);

            // Links: remember (text, href), keep only the text. The href can be in double
            // quotes, single quotes, or no quotes at all.
            s = Regex.Replace(s,
                @"<a\b[^>]*?\bhref\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>""']+))[^>]*>(.*?)</a\s*>", m =>
            {
                string rawHref = m.Groups[1].Success ? m.Groups[1].Value
                    : (m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value);
                string href = WebUtility.HtmlDecode(rawHref).Trim();
                string text = CleanText(WebUtility.HtmlDecode(Regex.Replace(m.Groups[4].Value, "<[^>]+>", " ")));
                if (href.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    links.Add(new MessageRecord.UrlRef(text, href));
                }
                return " " + text + " ";
            }, options);

            // Line breaks where the page would show them, then drop every remaining tag
            s = Regex.Replace(s, @"<(br|/p|/div|/tr|/li|/h[1-6]|/table)\b[^>]*>", "\n", options);
            s = Regex.Replace(s, "<[^>]+>", " ", options);
            s = WebUtility.HtmlDecode(s);

            // Tidy whitespace: collapse spaces within lines, drop blank lines
            List<string> lines = new List<string>();
            foreach (string line in s.Split('\n'))
            {
                string clean = CleanText(line);
                if (clean.Length > 0)
                {
                    lines.Add(clean);
                }
            }
            return string.Join("\n", lines);
        }

        // ------------------------------------------------------------------
        // Hidden text
        // ------------------------------------------------------------------

        /*
         * "Hidden text salting": scammers paste a few paragraphs of harmless text (a news
         * article, a Wikipedia page) into a phishing email and hide it, so the reader never sees
         * it but a filter reads a nice, boring article. It works on filters that read text,
         * which includes this one, so hidden parts are thrown away before the model sees them.
         *
         * An element counts as hidden when its tag says so:
         *   the hidden attribute               <div hidden>
         *   display:none, visibility:hidden    the browser doesn't draw it at all
         *   mso-hide:all                       Outlook's own "don't show this"
         *   opacity:0                          drawn fully see-through
         *   font-size of 0 or 1px              too small to see
         *   height:0 or max-height:0 with overflow:hidden   squashed flat
         *   white text, when nothing in the email has a non-white background (white on white)
         * Only the element's OWN tag is checked, not CSS rules in a <style> block, so this
         * catches the common tricks rather than every possible one.
         *
         * Legit emails hide things too (a "preview line" for the inbox list), but losing those
         * costs nothing: they aren't part of what the reader sees in the message.
         */
        // Tags and styles are matched ignoring case, and "." may match line breaks inside a tag.
        private static readonly RegexOptions TagOptions = RegexOptions.IgnoreCase | RegexOptions.Singleline;
        // An opening tag: <name attributes>
        private static readonly Regex StartTag = new Regex(@"<([a-z][a-z0-9]*)\b([^>]*)>", TagOptions);
        // A style="..." attribute
        private static readonly Regex StyleAttribute = new Regex(@"\bstyle\s*=\s*(?:""([^""]*)""|'([^']*)')", TagOptions);
        // The hidden attribute
        private static readonly Regex HiddenAttribute = new Regex(@"(?:^|\s)hidden(?:\s|=|/|$)", TagOptions);
        // font-size: 12px
        private static readonly Regex FontSize = new Regex(@"font-size\s*:\s*([0-9]*\.?[0-9]+)\s*(px|pt)?", TagOptions);
        // The styles that hide an element completely.
        private static readonly Regex HiddenStyle = new Regex(
            @"display\s*:\s*none|visibility\s*:\s*hidden|mso-hide\s*:\s*all|opacity\s*:\s*0*\.?0+\s*(?:;|!|$)", TagOptions);
        // height: 0 (squashed flat)
        private static readonly Regex Squashed = new Regex(@"(?:^|[;\s])(?:max-)?height\s*:\s*0+(?:px)?\s*(?:;|!|$)", TagOptions);
        // overflow: hidden (needed with height: 0)
        private static readonly Regex OverflowHidden = new Regex(@"overflow\s*:\s*hidden", TagOptions);
        // "color:" that isn't the end of "background-color:"
        private static readonly Regex TextColor = new Regex(@"(?<![-a-z])color\s*:\s*([^;]+)", TagOptions);
        // <font color="white">
        private static readonly Regex FontColor = new Regex(@"\bcolor\s*=\s*[""']?([^""'\s>]+)", TagOptions);
        // Any background color or picture, in its CSS or old-HTML forms (for white-on-white).
        private static readonly Regex Background = new Regex(
            @"background(?:-color|-image)?\s*:\s*([^;""']+)|\bbgcolor\s*=\s*[""']?([^""'\s>]+)|\bbackground\s*=\s*[""']?([^""'\s>]+)", TagOptions);
        // Tags that never have a closing tag
        private static readonly HashSet<string> VoidTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "img", "br", "hr", "input", "meta", "link", "area", "base", "col", "wbr", "source"
        };

        // The HTML with every hidden element (and everything inside it) removed. See above for
        // what counts as hidden.
        public static string RemoveHiddenElements(string html)
        {
            bool whiteIsHidden = !HasNonWhiteBackground(html);
            StringBuilder output = new StringBuilder(html.Length);
            int position = 0;
            while (position < html.Length)
            {
                Match tag = StartTag.Match(html, position);
                if (!tag.Success)
                {
                    break;
                }
                string name = tag.Groups[1].Value;
                Hiding how = HowHidden(name, tag.Groups[2].Value, whiteIsHidden);
                int afterTag = tag.Index + tag.Length;
                bool isVoid = tag.Value.EndsWith("/>") || VoidTags.Contains(name);
                int end = how == Hiding.No || isVoid ? afterTag : MatchingEnd(html, name, afterTag);

                // Some hiding can be undone by something inside the element. Email templates often
                // set font-size:0 on a box (to remove gaps between pictures) and then give the text
                // inside a normal size again. Those boxes are kept.
                if (how != Hiding.No && end > afterTag)
                {
                    string inner = html.Substring(afterTag, end - afterTag);
                    if ((how == Hiding.TinyFont && Regex.IsMatch(inner, @"font-size\s*:\s*0*[1-9]|<font\b[^>]*\bsize", TagOptions))
                        || (how == Hiding.WhiteText && Regex.IsMatch(inner, @"(?<![-a-z])color\s*:|<font\b[^>]*\bcolor", TagOptions))
                        || (how == Hiding.Invisible && Regex.IsMatch(inner, @"visibility\s*:\s*visible", TagOptions)))
                    {
                        how = Hiding.No;
                    }
                }
                if (how == Hiding.No)
                {
                    output.Append(html, position, afterTag - position);   // keep the tag; carry on inside it
                    position = afterTag;
                    continue;
                }
                output.Append(html, position, tag.Index - position);   // the text before the hidden element
                output.Append(' ');
                // A hidden tag that's never closed: drop just the tag and keep what follows,
                // rather than risk throwing away the rest of the email.
                position = end >= 0 ? end : afterTag;
            }
            if (position < html.Length)
            {
                output.Append(html, position, html.Length - position);
            }
            return output.ToString();
        }

        // Where the element that starts at `from` ends: just past its closing tag, counting
        // nested tags with the same name (<div><div></div></div>). -1 if it never closes.
        private static int MatchingEnd(string html, string name, int from)
        {
            Regex sameName = new Regex(@"<(/?)" + Regex.Escape(name) + @"\b[^>]*>", TagOptions);
            int depth = 1;
            Match m = sameName.Match(html, from);
            while (m.Success)
            {
                if (m.Groups[1].Value == "/")
                {
                    depth--;
                }
                else if (!m.Value.EndsWith("/>"))
                {
                    depth++;
                }
                if (depth == 0)
                {
                    return m.Index + m.Length;
                }
                m = m.NextMatch();
            }
            return -1;
        }

        // How a tag hides its contents. Always: nothing inside can show again. The others can be
        // undone by an element inside (see RemoveHiddenElements).
        private enum Hiding { No, Always, Invisible, TinyFont, WhiteText }

        // Does this tag hide what's inside it, and how? `whiteIsHidden` is true when nothing in the
        // email has a non-white background, so white text can't be seen.
        private static Hiding HowHidden(string name, string attributes, bool whiteIsHidden)
        {
            if (HiddenAttribute.IsMatch(attributes))
            {
                return Hiding.Always;
            }
            if (whiteIsHidden && name.Equals("font", StringComparison.OrdinalIgnoreCase))
            {
                Match fontColor = FontColor.Match(attributes);
                if (fontColor.Success && IsWhite(fontColor.Groups[1].Value))
                {
                    return Hiding.WhiteText;
                }
            }
            Match styleMatch = StyleAttribute.Match(attributes);
            if (!styleMatch.Success)
            {
                return Hiding.No;
            }
            string style = styleMatch.Groups[1].Success ? styleMatch.Groups[1].Value : styleMatch.Groups[2].Value;
            style = WebUtility.HtmlDecode(style);
            Match hidden = HiddenStyle.Match(style);
            if (hidden.Success)
            {
                return hidden.Value.StartsWith("visibility", StringComparison.OrdinalIgnoreCase) ? Hiding.Invisible : Hiding.Always;
            }
            if (Squashed.IsMatch(style) && OverflowHidden.IsMatch(style))
            {
                return Hiding.Always;
            }
            Match size = FontSize.Match(style);
            if (size.Success)
            {
                double value;
                if (double.TryParse(size.Groups[1].Value, System.Globalization.NumberStyles.Float,
                                    System.Globalization.CultureInfo.InvariantCulture, out value))
                {
                    bool absolute = size.Groups[2].Success;   // px or pt; 0.5em is a real size
                    if (value == 0 || (absolute && value <= 1))
                    {
                        return Hiding.TinyFont;
                    }
                }
            }
            if (whiteIsHidden)
            {
                Match color = TextColor.Match(style);
                if (color.Success && IsWhite(color.Groups[1].Value))
                {
                    return Hiding.WhiteText;
                }
            }
            return Hiding.No;
        }

        // True if any part of the email sets a background that isn't white, or a background
        // picture. Then white text may well be readable (white on a dark banner), so it's kept.
        private static bool HasNonWhiteBackground(string html)
        {
            foreach (Match m in Background.Matches(html))
            {
                string value = m.Groups[1].Success ? m.Groups[1].Value : (m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value);
                value = value.Trim().ToLowerInvariant();
                if (value.Length == 0 || value == "none" || value == "transparent" || value == "inherit" || value == "initial")
                {
                    continue;
                }
                if (!IsWhite(value))
                {
                    return true;
                }
            }
            return false;
        }

        // "#fff", "#FFFFFF", "white", "rgb(255,255,255)", and near-whites like "#fefefe"
        private static bool IsWhite(string color)
        {
            string c = color.Trim().ToLowerInvariant();
            int important = c.IndexOf('!');
            if (important >= 0)
            {
                c = c.Substring(0, important).Trim();   // "#fff !important"
            }
            if (c == "white")
            {
                return true;
            }
            Match rgb = Regex.Match(c, @"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)");
            if (rgb.Success)
            {
                return int.Parse(rgb.Groups[1].Value) >= 240 && int.Parse(rgb.Groups[2].Value) >= 240
                    && int.Parse(rgb.Groups[3].Value) >= 240;
            }
            Match hex = Regex.Match(c, @"^#?([0-9a-f]{3}|[0-9a-f]{6})$");
            if (!hex.Success)
            {
                return false;
            }
            string h = hex.Groups[1].Value;
            if (h.Length == 3)
            {
                h = "" + h[0] + h[0] + h[1] + h[1] + h[2] + h[2];   // "abc" -> "aabbcc"
            }
            int r = Convert.ToInt32(h.Substring(0, 2), 16);
            int g = Convert.ToInt32(h.Substring(2, 2), 16);
            int b = Convert.ToInt32(h.Substring(4, 2), 16);
            return r >= 240 && g >= 240 && b >= 240;
        }

        // The non-breaking space (&nbsp; in HTML) looks like a space but isn't one; turn it into one.
        private const char NonBreakingSpace = (char) 0x00A0;

        // Turns non-breaking spaces into normal ones and squeezes runs of spaces into one.
        private static string CleanText(string s)
        {
            return Regex.Replace(s.Replace(NonBreakingSpace, ' '), @"[ \t\r]+", " ").Trim();
        }
    }
}
