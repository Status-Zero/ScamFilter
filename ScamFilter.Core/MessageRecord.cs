using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ScamFilter
{
    /*
     * One message (a text or an email) in the project's common record format.
     *
     * Messages arrive in very different shapes: pasted text, an .eml email file, text read
     * out of a screenshot. Every one of them gets converted into this same shape first, so the
     * rest of the program (features, model, detector) only ever deals with one kind of input.
     * That also guarantees the model sees data the same way during training and in real use.
     *
     * On disk, records are stored in a JSONL file ("JSON Lines"): each line is one complete
     * JSON object, which makes it easy to append records and to read them one at a time.
     * See README.md for an example record.
     *
     * Unknown values:  "" for strings,  null for bool? fields,  -1 for numbers.
     * Unknown always means "no evidence either way", never "safe".
     */
    public class MessageRecord
    {
        // A link: what the reader sees (Display) and where it actually goes (Href).
        public class UrlRef
        {
            public string Display;   // what the link says on screen
            public string Href;      // where it really goes

            public UrlRef(string display, string href)
            {
                Display = display == null ? "" : display;
                Href = href == null ? "" : href;
            }
        }

        public string Type = "text";                     // "text" or "email"
        public string Sender = "";                       // phone number or email address
        public string DisplayName = "";                  // email "From" name, e.g. "PayPal Support"
        public string ReplyTo = "";                      // email Reply-To address (where your reply would go)
        public string Subject = "";                      // email subject ("" for texts)
        public string BodyText = "";                     // visible text, including the visible text of links
        public string ImageText = "";                    // OCR output from images in the message
        public List<UrlRef> Urls = new List<UrlRef>();   // links whose real target is known
        public string Spf = "";                          // sender checks the mail server already ran:
        public string Dkim = "";                         //   "pass", "fail", "softfail", "none" (see MetadataFeatures)
        public string Dmarc = "";                        // (see Spf)
        public bool? SenderIsContact = null;             // bool? (with the ?) can also be null, meaning unknown
        public bool? UserHasReplied = null;              // have you written to this sender before?
        public int DomainAgeDays = -1;                   // age of the linked domain, if something looked it up
        public int Label = -1;                           // the right answer: 1 = scam, 0 = not scam, -1 = unlabeled
        public string Source = "";                       // which dataset it came from (used to pick the test set)
        public string Channel = "raw";                   // "raw", "ocr", or "ocr_sim" (a simulated OCR copy)

        // Is it an email (not a text message)?
        public bool IsEmail()
        {
            return Type == "email";
        }

        // Was the text read from a picture (a screenshot), or made to look like it was?
        public bool IsOcr()
        {
            return Channel.StartsWith("ocr", StringComparison.Ordinal);
        }

        // All the readable text the text model looks at.
        public string FullText()
        {
            return Subject + "\n" + BodyText + "\n" + ImageText;
        }

        // The first few characters of the text on one line, for reports and lists.
        public string Preview(int maxLength)
        {
            string flat = System.Text.RegularExpressions.Regex.Replace(FullText(), @"\s+", " ").Trim();
            if (flat.Length <= maxLength)
            {
                return flat;
            }
            return flat.Substring(0, maxLength) + "...";
        }

        // A separate copy, so changing it doesn't change the original.
        public MessageRecord Copy()
        {
            MessageRecord c = new MessageRecord();
            c.Type = Type;
            c.Sender = Sender;
            c.DisplayName = DisplayName;
            c.ReplyTo = ReplyTo;
            c.Subject = Subject;
            c.BodyText = BodyText;
            c.ImageText = ImageText;
            c.Urls = new List<UrlRef>();
            foreach (UrlRef u in Urls)
            {
                c.Urls.Add(new UrlRef(u.Display, u.Href));
            }
            c.Spf = Spf;
            c.Dkim = Dkim;
            c.Dmarc = Dmarc;
            c.SenderIsContact = SenderIsContact;
            c.UserHasReplied = UserHasReplied;
            c.DomainAgeDays = DomainAgeDays;
            c.Label = Label;
            c.Source = Source;
            c.Channel = Channel;
            return c;
        }

        // ------------------------------------------------------------------
        // Reading JSON (System.Text.Json does the parsing; these helpers read fields safely)
        // A missing key and an explicit null both mean "unknown".
        // ------------------------------------------------------------------

        public static MessageRecord FromJsonText(string json)
        {
            JsonDocument document = JsonDocument.Parse(json);
            try
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new FormatException("expected a JSON object { ... }");
                }
                return FromJson(document.RootElement);
            }
            finally
            {
                document.Dispose();   // JsonDocument borrows pooled memory, so it must be released
            }
        }

        // Builds a record from one parsed JSON object (missing fields keep their defaults).
        public static MessageRecord FromJson(JsonElement obj)
        {
            MessageRecord r = new MessageRecord();
            string type = GetString(obj, "type").Trim().ToLowerInvariant();
            r.Type = type == "email" ? "email" : "text";
            r.Sender = GetString(obj, "sender").Trim();
            r.DisplayName = GetString(obj, "display_name").Trim();
            r.ReplyTo = GetString(obj, "reply_to").Trim();
            r.Subject = GetString(obj, "subject");
            r.BodyText = GetString(obj, "body_text");
            r.ImageText = GetString(obj, "image_text");

            JsonElement urls;
            if (obj.TryGetProperty("urls", out urls) && urls.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in urls.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object)
                    {
                        r.Urls.Add(new UrlRef(GetString(item, "display"), GetString(item, "href")));
                    }
                    else if (item.ValueKind == JsonValueKind.String)
                    {
                        r.Urls.Add(new UrlRef(item.GetString(), item.GetString()));
                    }
                }
            }

            JsonElement auth;
            if (obj.TryGetProperty("auth", out auth) && auth.ValueKind == JsonValueKind.Object)
            {
                r.Spf = GetString(auth, "spf").Trim().ToLowerInvariant();
                r.Dkim = GetString(auth, "dkim").Trim().ToLowerInvariant();
                r.Dmarc = GetString(auth, "dmarc").Trim().ToLowerInvariant();
            }

            r.SenderIsContact = GetBool(obj, "sender_is_contact");
            if (r.SenderIsContact == null)
            {
                r.SenderIsContact = GetBool(obj, "prior_contact");
            }
            r.UserHasReplied = GetBool(obj, "user_has_replied");
            r.DomainAgeDays = GetInt(obj, "domain_age_days", -1);
            JsonElement label;
            r.Label = obj.TryGetProperty("label", out label) ? ParseLabel(label) : -1;
            r.Source = GetString(obj, "source").Trim();
            string channel = GetString(obj, "channel").Trim().ToLowerInvariant();
            r.Channel = channel.Length == 0 ? "raw" : channel;
            return r;
        }

        // Missing/null -> "". Whole numbers come back without a decimal point.
        private static string GetString(JsonElement obj, string key)
        {
            JsonElement value;
            if (!obj.TryGetProperty(key, out value))
            {
                return "";
            }
            switch (value.ValueKind)
            {
                case JsonValueKind.String:
                    return value.GetString();
                case JsonValueKind.Number:
                    return value.GetRawText();
                case JsonValueKind.True:
                    return "true";
                case JsonValueKind.False:
                    return "false";
                default:
                    return "";
            }
        }

        // Missing/null -> null (unknown). Accepts true/false, 1/0, "yes"/"no".
        private static bool? GetBool(JsonElement obj, string key)
        {
            JsonElement value;
            if (!obj.TryGetProperty(key, out value))
            {
                return null;
            }
            if (value.ValueKind == JsonValueKind.True)
            {
                return true;
            }
            if (value.ValueKind == JsonValueKind.False)
            {
                return false;
            }
            if (value.ValueKind == JsonValueKind.Number)
            {
                return value.GetDouble() != 0.0;
            }
            if (value.ValueKind == JsonValueKind.String)
            {
                string s = value.GetString().Trim().ToLowerInvariant();
                if (s == "true" || s == "yes" || s == "1")
                {
                    return true;
                }
                if (s == "false" || s == "no" || s == "0")
                {
                    return false;
                }
            }
            return null;
        }

        // Missing/null/unparseable -> fallback.
        private static int GetInt(JsonElement obj, string key, int fallback)
        {
            JsonElement value;
            if (!obj.TryGetProperty(key, out value))
            {
                return fallback;
            }
            if (value.ValueKind == JsonValueKind.Number)
            {
                return (int) Math.Floor(value.GetDouble() + 0.5);
            }
            if (value.ValueKind == JsonValueKind.String)
            {
                int parsed;
                if (int.TryParse(value.GetString().Trim(), out parsed))
                {
                    return parsed;
                }
            }
            return fallback;
        }

        // Accepts 1/0, true/false, or words: "scam"/"unsafe" -> 1, "safe"/"legit"/"spam"/"ham" -> 0.
        private static int ParseLabel(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Number)
            {
                return value.GetDouble() >= 0.5 ? 1 : 0;
            }
            if (value.ValueKind == JsonValueKind.True)
            {
                return 1;
            }
            if (value.ValueKind == JsonValueKind.False)
            {
                return 0;
            }
            if (value.ValueKind == JsonValueKind.String)
            {
                string s = value.GetString().Trim().ToLowerInvariant();
                if (s == "1" || s == "scam" || s == "unsafe")
                {
                    return 1;
                }
                if (s == "0" || s == "safe" || s == "legit" || s == "not_scam" || s == "spam" || s == "ham")
                {
                    return 0;
                }
            }
            return -1;
        }

        // Reads a JSONL file: one JSON object per line, blank lines skipped.
        public static List<MessageRecord> LoadJsonl(string path)
        {
            List<MessageRecord> records = new List<MessageRecord>();
            StreamReader reader = DataFiles.OpenReader(path);
            string line = reader.ReadLine();
            int lineNumber = 1;
            while (line != null)
            {
                if (lineNumber == 1)
                {
                    line = DataFiles.StripBom(line);
                }
                string trimmed = line.Trim();
                if (trimmed.Length > 0)
                {
                    try
                    {
                        records.Add(FromJsonText(trimmed));
                    }
                    catch (Exception e) when (e is JsonException || e is FormatException)
                    {
                        reader.Close();
                        throw new IOException(path + " line " + lineNumber + ": " + e.Message);
                    }
                }
                line = reader.ReadLine();
                lineNumber++;
            }
            reader.Close();
            return records;
        }

        // ------------------------------------------------------------------
        // Writing JSON (used to save corrections from the app as new training records)
        // Unknown fields are left out, which reads back as unknown.
        // ------------------------------------------------------------------

        public string ToJsonLine()
        {
            MemoryStream stream = new MemoryStream();
            JsonWriterOptions options = new JsonWriterOptions();
            options.Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;   // keep ' and accents readable
            Utf8JsonWriter w = new Utf8JsonWriter(stream, options);
            w.WriteStartObject();
            w.WriteString("type", Type);
            WriteIfPresent(w, "sender", Sender);
            WriteIfPresent(w, "display_name", DisplayName);
            WriteIfPresent(w, "reply_to", ReplyTo);
            WriteIfPresent(w, "subject", Subject);
            w.WriteString("body_text", BodyText);
            WriteIfPresent(w, "image_text", ImageText);
            if (Urls.Count > 0)
            {
                w.WriteStartArray("urls");
                foreach (UrlRef u in Urls)
                {
                    w.WriteStartObject();
                    w.WriteString("display", u.Display);
                    w.WriteString("href", u.Href);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
            }
            if (Spf.Length > 0 || Dkim.Length > 0 || Dmarc.Length > 0)
            {
                w.WriteStartObject("auth");
                WriteIfPresent(w, "spf", Spf);
                WriteIfPresent(w, "dkim", Dkim);
                WriteIfPresent(w, "dmarc", Dmarc);
                w.WriteEndObject();
            }
            if (SenderIsContact != null)
            {
                w.WriteBoolean("sender_is_contact", SenderIsContact.Value);
            }
            if (UserHasReplied != null)
            {
                w.WriteBoolean("user_has_replied", UserHasReplied.Value);
            }
            if (DomainAgeDays >= 0)
            {
                w.WriteNumber("domain_age_days", DomainAgeDays);
            }
            w.WriteNumber("label", Label);
            WriteIfPresent(w, "source", Source);
            w.WriteString("channel", Channel);
            w.WriteEndObject();
            w.Flush();
            string json = Encoding.UTF8.GetString(stream.ToArray());
            w.Dispose();
            stream.Close();
            return json;
        }

        // Writes "key": "value" only when there's a value, to keep records.jsonl small.
        private static void WriteIfPresent(Utf8JsonWriter w, string key, string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                w.WriteString(key, value);
            }
        }
    }
}
