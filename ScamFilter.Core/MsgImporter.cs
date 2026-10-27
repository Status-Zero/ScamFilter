using System;
using System.IO;
using MsgReader.Outlook;

namespace ScamFilter
{
    /*
     * Turns an Outlook .msg file into a MessageRecord: the email connector for classic Outlook.
     *
     * A .msg file is what you get by dragging an email out of classic Outlook (the desktop app)
     * onto the desktop. Dragging one straight from Outlook into ScamFilter hands over the same
     * bytes. Inside, it's a "compound file": a little file system packed into one file, the same
     * container old .doc and .xls files use. MsgReader (a library) unpacks it.
     *
     * Emails that came in over the internet keep their original headers inside the .msg
     * ("transport headers"), so the sender checks (SPF / DKIM / DMARC) work exactly like they do
     * for .eml files. Emails sent inside one organization's Exchange server don't have those.
     */
    public static class MsgImporter
    {
        // Reads an Outlook .msg file from disk.
        public static EmlImporter.Result Load(string path)
        {
            FileStream stream = File.OpenRead(path);
            try
            {
                return Load(stream);
            }
            finally
            {
                stream.Close();
            }
        }

        // True if these bytes start like a compound file (the .msg container): D0 CF 11 E0 A1 B1 1A E1.
        public static bool LooksLikeMsg(byte[] start)
        {
            byte[] signature = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
            if (start == null || start.Length < signature.Length)
            {
                return false;
            }
            for (int i = 0; i < signature.Length; i++)
            {
                if (start[i] != signature[i])
                {
                    return false;
                }
            }
            return true;
        }

        // Reads a .msg from a stream: the same fields as an .eml (sender, subject, visible text,
        // real link targets, sender checks, pictures).
        public static EmlImporter.Result Load(Stream stream)
        {
            Storage.Message msg = new Storage.Message(stream, FileAccess.Read, true);
            try
            {
                EmlImporter.Result result = new EmlImporter.Result();
                MessageRecord r = new MessageRecord();
                r.Type = "email";
                r.Channel = "raw";

                if (msg.Sender != null)
                {
                    // Senders inside the same Exchange organization can show up as long internal
                    // names ("/O=EXCHANGELABS/OU=...") instead of email addresses; keep only real addresses.
                    string email = msg.Sender.Email ?? "";
                    r.Sender = email.IndexOf('@') > 0 ? email.Trim() : "";
                    r.DisplayName = (msg.Sender.DisplayName ?? "").Trim();
                }
                r.Subject = msg.Subject ?? "";

                string html = msg.BodyHtml;
                if (!string.IsNullOrEmpty(html))
                {
                    r.BodyText = EmlImporter.HtmlToText(html, r.Urls);
                }
                else if (!string.IsNullOrEmpty(msg.BodyText))
                {
                    r.BodyText = msg.BodyText;
                }

                EmlImporter.ApplyHeaderText(msg.TransportMessageHeaders, r);

                foreach (object item in msg.Attachments)
                {
                    Storage.Attachment attachment = item as Storage.Attachment;
                    if (attachment != null && attachment.Data != null && IsImage(attachment)
                        && result.Images.Count < EmlImporter.MaxImages)
                    {
                        result.Images.Add(attachment.Data);
                    }
                }
                result.Record = r;
                return result;
            }
            finally
            {
                msg.Dispose();
            }
        }

        // Is this attachment a picture (by its type, or by its file name)?
        private static bool IsImage(Storage.Attachment attachment)
        {
            string type = attachment.MimeType ?? "";
            if (type.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            string ext = Path.GetExtension(attachment.FileName ?? "").ToLowerInvariant();
            return ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".bmp";
        }
    }
}
