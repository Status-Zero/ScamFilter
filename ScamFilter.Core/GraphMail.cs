using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace ScamFilter
{
    /*
     * Reads mail from a linked Outlook account (Outlook.com, Hotmail, Live, or a work or school
     * Microsoft 365 mailbox) through Microsoft Graph, Microsoft's web API for its services.
     * Nothing AI here: this is another "connector", like EmlImporter, and every email it reads
     * becomes the same MessageRecord the model was trained on.
     *
     * How Graph works, in short: you send a normal web request to an address like
     *     GET https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages
     * with a header "Authorization: Bearer <access token>", and get JSON back. The access token
     * proves the user signed in and agreed to let this app read their mail. Getting the token
     * (the "Sign in with Microsoft" part) is the desktop app's job (OutlookAccount in the
     * desktop project), so this class only asks for one through `getToken` when it needs it.
     *
     * Reading uses the Mail.Read permission, which can't change anything in the mailbox. The one
     * exception is SendMailAsync, for alerts, which needs Mail.Send; that permission is only
     * asked for when the user turns alerts on. Nothing here can delete or move mail.
     *
     * What it does:
     *   ListAsync           the newest emails in a folder, as records ready to check
     *   DownloadMimeAsync   one whole email as an .eml file (with its pictures, for OCR)
     *   HaveSentToAsync     "have I ever emailed this address?" (the user_has_replied flag)
     *   GetDisplayNameAsync the signed-in person's name
     *   SendMailAsync       an alert email to a trusted contact (see AlertComposer)
     */
    public class GraphMailClient
    {
        public const string BaseUrl = "https://graph.microsoft.com/v1.0";

        // The well-known folder names Graph understands
        public const string Inbox = "inbox";
        public const string Junk = "junkemail";   // Graph's name for the Junk Email folder

        // One HttpClient for the whole program: making a new one per request wastes connections.
        private static readonly HttpClient Http = CreateHttpClient();

        private readonly Func<CancellationToken, Task<string>> getToken;

        public GraphMailClient(Func<CancellationToken, Task<string>> getToken)
        {
            this.getToken = getToken;
        }

        // The shared HttpClient: a 60-second timeout, and a name Microsoft sees in its logs.
        private static HttpClient CreateHttpClient()
        {
            HttpClient client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(60);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("ScamFilter/1.5");
            return client;
        }

        // One email in a folder listing.
        public class MailItem
        {
            public string Id = "";            // Graph's ID for the email (used to download all of it)
            public string FromName = "";      // the sender's display name
            public string FromAddress = "";   // the sender's address
            public string Subject = "";       // the subject line
            public DateTimeOffset Received;   // when it arrived
            public bool IsRead = true;        // false = still unread in Outlook
            public string WebLink = "";       // opens the email in Outlook on the web
            public MessageRecord Record;      // ready for ScamDetector.Check
        }

        // ------------------------------------------------------------------
        // Listing a folder
        // ------------------------------------------------------------------

        /*
         * The newest `count` emails in a folder (Inbox or Junk), newest first.
         *
         * $select asks for only the fields we use. internetMessageHeaders (the raw headers, which
         * carry the SPF / DKIM / DMARC results) is only sent when asked for by name like this.
         * The body comes as HTML, which is what we want: only HTML links carry where they
         * really go, separately from the text you see.
         */
        public async Task<List<MailItem>> ListAsync(string folder, int count, CancellationToken cancel)
        {
            string url = BaseUrl + "/me/mailFolders/" + folder + "/messages"
                + "?$top=" + count.ToString(CultureInfo.InvariantCulture)
                + "&$orderby=receivedDateTime%20desc"
                + "&$select=id,subject,from,replyTo,receivedDateTime,isRead,webLink,body,internetMessageHeaders";
            string json = await GetStringAsync(url, cancel);
            List<MailItem> items = new List<MailItem>();
            JsonDocument doc = JsonDocument.Parse(json);
            try
            {
                JsonElement list;
                if (doc.RootElement.TryGetProperty("value", out list) && list.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement message in list.EnumerateArray())
                    {
                        items.Add(Parse(message));
                    }
                }
            }
            finally
            {
                doc.Dispose();
            }
            return items;
        }

        /*
         * One message from Graph's JSON -> a MailItem with its MessageRecord.
         * (Public so the tests can feed it sample JSON.) The JSON looks like:
         *   { "id": "AAMk...", "subject": "...", "isRead": false,
         *     "receivedDateTime": "2026-10-20T14:03:11Z",
         *     "from": { "emailAddress": { "name": "PayPal", "address": "service@paypal.com" } },
         *     "replyTo": [ { "emailAddress": { "address": "..." } } ],
         *     "body": { "contentType": "html", "content": "<html>..." },
         *     "internetMessageHeaders": [ { "name": "Authentication-Results", "value": "spf=pass ..." }, ... ] }
         */
        public static MailItem Parse(JsonElement m)
        {
            MailItem item = new MailItem();
            item.Id = Str(m, "id");
            item.Subject = Str(m, "subject");
            item.WebLink = Str(m, "webLink");
            JsonElement isRead;
            if (m.TryGetProperty("isRead", out isRead) && (isRead.ValueKind == JsonValueKind.True || isRead.ValueKind == JsonValueKind.False))
            {
                item.IsRead = isRead.GetBoolean();
            }
            DateTimeOffset received;
            if (DateTimeOffset.TryParse(Str(m, "receivedDateTime"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out received))
            {
                item.Received = received;
            }

            JsonElement from;
            JsonElement address;
            if (m.TryGetProperty("from", out from) && from.ValueKind == JsonValueKind.Object
                && from.TryGetProperty("emailAddress", out address) && address.ValueKind == JsonValueKind.Object)
            {
                item.FromName = Str(address, "name");
                item.FromAddress = Str(address, "address");
            }

            MessageRecord r = new MessageRecord();
            r.Type = "email";
            r.Channel = "raw";
            r.Source = "outlook";
            r.Label = -1;
            r.Sender = item.FromAddress;
            r.DisplayName = item.FromName;
            r.Subject = item.Subject;

            JsonElement replyTo;
            if (m.TryGetProperty("replyTo", out replyTo) && replyTo.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement reply in replyTo.EnumerateArray())
                {
                    JsonElement replyAddress;
                    if (reply.TryGetProperty("emailAddress", out replyAddress) && replyAddress.ValueKind == JsonValueKind.Object)
                    {
                        r.ReplyTo = Str(replyAddress, "address");
                        break;   // only the first one matters
                    }
                }
            }

            JsonElement body;
            if (m.TryGetProperty("body", out body) && body.ValueKind == JsonValueKind.Object)
            {
                string content = Str(body, "content");
                bool isHtml = Str(body, "contentType").Equals("html", StringComparison.OrdinalIgnoreCase);
                r.BodyText = isHtml ? EmlImporter.HtmlToText(content, r.Urls) : content;
            }

            // The raw headers, rebuilt as "Name: value" lines for the same code that reads .msg files.
            JsonElement headers;
            if (m.TryGetProperty("internetMessageHeaders", out headers) && headers.ValueKind == JsonValueKind.Array)
            {
                StringBuilder raw = new StringBuilder();
                foreach (JsonElement header in headers.EnumerateArray())
                {
                    string name = Str(header, "name");
                    if (name.Length > 0)
                    {
                        // Header values can't contain line breaks, or the next line would look like a new header.
                        raw.Append(name).Append(": ").Append(Str(header, "value").Replace("\r", " ").Replace("\n", " ")).Append("\r\n");
                    }
                }
                EmlImporter.ApplyHeaderText(raw.ToString(), r);
            }
            item.Record = r;
            return item;
        }

        // A string property, or "" when it's missing or null.
        private static string Str(JsonElement e, string name)
        {
            JsonElement value;
            if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }
            return "";
        }

        // ------------------------------------------------------------------
        // One whole email
        // ------------------------------------------------------------------

        // The complete email in .eml form ("MIME"), pictures and attachments included.
        public async Task<byte[]> DownloadMimeAsync(string id, CancellationToken cancel)
        {
            HttpResponseMessage response = await SendAsync(BaseUrl + "/me/messages/" + Uri.EscapeDataString(id) + "/$value", cancel);
            try
            {
                return await response.Content.ReadAsByteArrayAsync(cancel);
            }
            finally
            {
                response.Dispose();
            }
        }

        // ------------------------------------------------------------------
        // "Have I emailed them before?"
        // ------------------------------------------------------------------

        /*
         * Searches Sent Items for anything sent to `address`. true = yes, false = no, and
         * null = couldn't tell (the search failed). Like the check box on the Check page, a "no"
         * is passed on as "unknown", never as evidence: lots of real senders are ones you never
         * write back to.
         */
        public async Task<bool?> HaveSentToAsync(string address, CancellationToken cancel)
        {
            if (address.IndexOf('@') <= 0 || address.IndexOf('"') >= 0)
            {
                return null;
            }
            string search = Uri.EscapeDataString("\"to:" + address + "\"");
            string url = BaseUrl + "/me/mailFolders/sentitems/messages?$search=" + search + "&$top=1&$select=id";
            try
            {
                string json = await GetStringAsync(url, cancel);
                JsonDocument doc = JsonDocument.Parse(json);
                try
                {
                    JsonElement list;
                    return doc.RootElement.TryGetProperty("value", out list) && list.ValueKind == JsonValueKind.Array
                        && list.GetArrayLength() > 0;
                }
                finally
                {
                    doc.Dispose();
                }
            }
            catch (GraphException)
            {
                return null;   // a failed search just means "don't know"
            }
            catch (HttpRequestException)
            {
                return null;
            }
        }

        // ------------------------------------------------------------------
        // Who's signed in
        // ------------------------------------------------------------------

        // The signed-in person's name as Microsoft has it ("Jordan M."), or "" if it can't be read.
        public async Task<string> GetDisplayNameAsync(CancellationToken cancel)
        {
            try
            {
                string json = await GetStringAsync(BaseUrl + "/me?$select=displayName", cancel);
                JsonDocument doc = JsonDocument.Parse(json);
                try
                {
                    return Str(doc.RootElement, "displayName");
                }
                finally
                {
                    doc.Dispose();
                }
            }
            catch (GraphException)
            {
                return "";
            }
        }

        // ------------------------------------------------------------------
        // Sending an alert
        // ------------------------------------------------------------------

        /*
         * Sends one plain-text email from the signed-in account, using the Mail.Send permission.
         * That permission is only asked for when alerts are turned on, and this is the ONLY thing
         * the app ever sends: alerts to the contacts the user picked. A copy goes into the user's
         * Sent Items, so they can always see exactly what was sent in their name.
         *
         *   POST /me/sendMail
         *   { "message": { "subject": "...", "body": { "contentType": "Text", "content": "..." },
         *                  "toRecipients": [ { "emailAddress": { "address": "..." } } ] },
         *     "saveToSentItems": true }
         */
        public async Task SendMailAsync(string to, string subject, string body,
                                        Func<CancellationToken, Task<string>> sendToken, CancellationToken cancel)
        {
            MemoryStream buffer = new MemoryStream();
            Utf8JsonWriter w = new Utf8JsonWriter(buffer);
            w.WriteStartObject();
            w.WriteStartObject("message");
            w.WriteString("subject", subject);
            w.WriteStartObject("body");
            w.WriteString("contentType", "Text");
            w.WriteString("content", body);
            w.WriteEndObject();
            w.WriteStartArray("toRecipients");
            w.WriteStartObject();
            w.WriteStartObject("emailAddress");
            w.WriteString("address", to);
            w.WriteEndObject();
            w.WriteEndObject();
            w.WriteEndArray();
            w.WriteEndObject();
            w.WriteBoolean("saveToSentItems", true);
            w.WriteEndObject();
            w.Flush();
            w.Dispose();
            string json = Encoding.UTF8.GetString(buffer.ToArray());
            buffer.Close();
            HttpResponseMessage response = await SendAsync(HttpMethod.Post, BaseUrl + "/me/sendMail", json, sendToken, cancel);
            response.Dispose();   // success is "202 Accepted" with no body
        }

        // ------------------------------------------------------------------
        // Sending requests
        // ------------------------------------------------------------------

        private async Task<string> GetStringAsync(string url, CancellationToken cancel)
        {
            HttpResponseMessage response = await SendAsync(url, cancel);
            try
            {
                return await response.Content.ReadAsStringAsync(cancel);
            }
            finally
            {
                response.Dispose();
            }
        }

        /*
         * GET with the access token. Two kinds of "try again" are handled here:
         *   429 Too Many Requests / 503 Unavailable: Graph is busy. It says how long to wait
         *       (the Retry-After header), so wait that long and retry, up to 3 times.
         *   401 Unauthorized: the token expired in the meantime. Ask for a fresh one once.
         * Anything else that isn't a success becomes a GraphException with Graph's own message.
         */
        private Task<HttpResponseMessage> SendAsync(string url, CancellationToken cancel)
        {
            return SendAsync(HttpMethod.Get, url, null, getToken, cancel);
        }

        // The full version: any HTTP method, an optional JSON body, and which token to send
        // (reading mail and sending alerts use different permissions).
        private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string url, string jsonBody,
                                                          Func<CancellationToken, Task<string>> tokenSource, CancellationToken cancel)
        {
            int attempt = 0;
            bool refreshedToken = false;
            while (true)
            {
                attempt++;
                string token = await tokenSource(cancel);
                HttpRequestMessage request = new HttpRequestMessage(method, url);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                if (jsonBody != null)
                {
                    request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
                }
                HttpResponseMessage response;
                try
                {
                    response = await Http.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancel);
                }
                finally
                {
                    request.Dispose();
                }
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }

                int status = (int) response.StatusCode;
                if ((status == 429 || status == 503) && attempt <= 3)
                {
                    TimeSpan wait = TimeSpan.FromSeconds(2 * attempt);
                    if (response.Headers.RetryAfter != null && response.Headers.RetryAfter.Delta.HasValue)
                    {
                        wait = response.Headers.RetryAfter.Delta.Value;
                    }
                    response.Dispose();
                    await Task.Delay(wait < TimeSpan.FromSeconds(30) ? wait : TimeSpan.FromSeconds(30), cancel);
                    continue;
                }
                if (status == 401 && !refreshedToken)
                {
                    refreshedToken = true;
                    response.Dispose();
                    continue;   // getToken hands out a fresh token when the old one has expired
                }

                string message = await ErrorMessage(response, cancel);
                response.Dispose();
                throw new GraphException(status, message);
            }
        }

        // Graph explains errors as JSON: { "error": { "code": "...", "message": "..." } }
        private static async Task<string> ErrorMessage(HttpResponseMessage response, CancellationToken cancel)
        {
            string text = "";
            try
            {
                text = await response.Content.ReadAsStringAsync(cancel);
                JsonDocument doc = JsonDocument.Parse(text);
                try
                {
                    JsonElement error;
                    JsonElement message;
                    if (doc.RootElement.TryGetProperty("error", out error) && error.TryGetProperty("message", out message)
                        && message.ValueKind == JsonValueKind.String)
                    {
                        return message.GetString();
                    }
                }
                finally
                {
                    doc.Dispose();
                }
            }
            catch (JsonException)
            {
                // not JSON: fall through to the status line
            }
            return "Outlook answered " + (int) response.StatusCode + " " + response.ReasonPhrase
                + (text.Length > 0 && text.Length < 200 ? ": " + text : "");
        }
    }

    // A request to Microsoft Graph that failed. Status is the HTTP status code (403 = not allowed, ...).
    public class GraphException : Exception
    {
        public readonly int Status;   // the HTTP status code

        public GraphException(int status, string message) : base(message)
        {
            Status = status;
        }
    }
}
