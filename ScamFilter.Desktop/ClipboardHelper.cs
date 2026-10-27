using System;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media.Imaging;

namespace ScamFilter.Desktop
{
    /*
     * Reads the clipboard safely. Copying puts the same thing on the clipboard in several
     * formats at once, and ScamFilter picks the most useful one:
     *
     *   "HTML Format"  copying from Outlook, Gmail, or a web page. This is the valuable one:
     *                  links keep their REAL destinations, not just the text you see.
     *   "PNG"          a screenshot (Win+Shift+S, Snipping Tool) or a picture copied from a
     *                  browser. Kept exactly as it was, best for OCR. (Some programs call it
     *                  "image/png".)
     *   Bitmap         a screenshot from the Print Screen key or an older program.
     *   DIB            the same picture as raw pixels ("device-independent bitmap"), which every
     *                  program that copies a picture also offers. The last resort for pictures.
     *   Text           plain text.
     *   FileDrop       files copied in File Explorer.
     *
     * Every read is wrapped in try/catch: if another program is holding the clipboard at that
     * moment, Windows refuses access, and that shouldn't crash anything.
     */
    public static class ClipboardHelper
    {
        // The names programs use for a PNG picture on the clipboard.
        private static readonly string[] PngFormats = { "PNG", "image/png" };

        // <img src="..."> in copied HTML (some web apps copy a picture only this way).
        private static readonly Regex ImageTag = new Regex("<img\\b[^>]*?\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        // Is there text on the clipboard?
        public static bool HasText()
        {
            try
            {
                return Clipboard.ContainsText();
            }
            catch (Exception)
            {
                return false;
            }
        }

        // The clipboard's plain text, or null.
        public static string GetText()
        {
            try
            {
                return Clipboard.ContainsText() ? Clipboard.GetText() : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /*
         * Is there text that's a message, rather than a label for a copied picture? When you
         * copy a picture, some programs also put its web address or file name on the clipboard as
         * text. One "word" with no spaces next to a picture is that kind of label.
         */
        public static bool HasMessageText()
        {
            string text = GetText();
            if (text == null || text.Trim().Length == 0)
            {
                return false;
            }
            string t = text.Trim();
            bool oneWord = t.IndexOfAny(new char[] { ' ', '\t', '\r', '\n' }) < 0;
            return !(oneWord && HasImage());
        }

        /*
         * Is there a picture on the clipboard (a screenshot, or a picture copied from an app or
         * a web page)? One look at the clipboard (GetDataObject) answers all the format questions.
         */
        public static bool HasImage()
        {
            try
            {
                IDataObject data = Clipboard.GetDataObject();
                if (data == null)
                {
                    return false;
                }
                foreach (string format in PngFormats)
                {
                    if (data.GetDataPresent(format, false))
                    {
                        return true;
                    }
                }
                if (data.GetDataPresent(DataFormats.Bitmap, true) || data.GetDataPresent(DataFormats.Dib, false))
                {
                    return true;
                }
                // Copied HTML that's only a picture (no text at all)
                return !data.GetDataPresent(DataFormats.UnicodeText, true) && GetHtmlImage() != null;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Are there files copied in File Explorer on the clipboard?
        public static bool HasFiles()
        {
            try
            {
                return Clipboard.ContainsFileDropList();
            }
            catch (Exception)
            {
                return false;
            }
        }

        // The picture as PNG file bytes, if a program put it on the clipboard that way, or null.
        public static byte[] GetPng()
        {
            foreach (string format in PngFormats)
            {
                try
                {
                    if (!Clipboard.ContainsData(format))
                    {
                        continue;
                    }
                    byte[] bytes = ToBytes(Clipboard.GetData(format));
                    if (bytes != null && bytes.Length > 8)
                    {
                        return bytes;
                    }
                }
                catch (Exception)
                {
                    // try the next format
                }
            }
            return null;
        }

        // The clipboard's picture as a bitmap (for programs that don't put a PNG there), or null.
        public static BitmapSource GetBitmap()
        {
            try
            {
                return Clipboard.ContainsImage() ? Clipboard.GetImage() : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /*
         * The clipboard's DIB, turned into the bytes of a .bmp file, or null.
         *
         * A DIB is a .bmp file without its first 14 bytes (the "file header"), so adding that
         * header back makes something Windows' picture readers can open. The header's one tricky
         * number is where the pixels start: after the info header, the color masks (only for
         * the old 40-byte header with "bitfields" compression), and the color table (only for
         * pictures with 256 colors or fewer).
         */
        public static byte[] GetDibAsBmp()
        {
            byte[] dib;
            try
            {
                if (!Clipboard.ContainsData(DataFormats.Dib))
                {
                    return null;
                }
                dib = ToBytes(Clipboard.GetData(DataFormats.Dib));
            }
            catch (Exception)
            {
                return null;
            }
            if (dib == null || dib.Length < 40)
            {
                return null;
            }
            int headerSize = BitConverter.ToInt32(dib, 0);
            int bitCount = BitConverter.ToUInt16(dib, 14);
            int compression = BitConverter.ToInt32(dib, 16);
            int colorsUsed = BitConverter.ToInt32(dib, 32);
            const int BiBitfields = 3;
            int masks = headerSize == 40 && compression == BiBitfields ? 12 : 0;
            int colors = colorsUsed != 0 ? colorsUsed : (bitCount <= 8 ? 1 << bitCount : 0);
            int pixelsStart = 14 + headerSize + masks + colors * 4;

            byte[] bmp = new byte[14 + dib.Length];
            bmp[0] = (byte) 'B';
            bmp[1] = (byte) 'M';
            BitConverter.GetBytes(bmp.Length).CopyTo(bmp, 2);   // file size
            BitConverter.GetBytes(pixelsStart).CopyTo(bmp, 10); // where the pixels start
            Buffer.BlockCopy(dib, 0, bmp, 14, dib.Length);
            return bmp;
        }

        /*
         * A picture that copied HTML only points to, as file bytes, or null: either written into
         * the HTML itself (src="data:image/png;base64,...") or a file on this PC
         * (src="file:///C:/..."). Web addresses are never downloaded.
         */
        public static byte[] GetHtmlImage()
        {
            string html = GetHtml();
            if (html == null)
            {
                return null;
            }
            Match img = ImageTag.Match(html);
            if (!img.Success)
            {
                return null;
            }
            string src = System.Net.WebUtility.HtmlDecode(img.Groups[1].Value).Trim();
            try
            {
                if (src.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase))
                {
                    int comma = src.IndexOf(',');
                    if (comma > 0 && src.Substring(0, comma).EndsWith(";base64", StringComparison.OrdinalIgnoreCase))
                    {
                        return Convert.FromBase64String(src.Substring(comma + 1));
                    }
                    return null;
                }
                Uri uri;
                if (Uri.TryCreate(src, UriKind.Absolute, out uri) && uri.IsFile && File.Exists(uri.LocalPath))
                {
                    return File.ReadAllBytes(uri.LocalPath);
                }
            }
            catch (Exception)
            {
                // a broken data: address or an unreadable file: no picture
            }
            return null;
        }

        // The files copied in File Explorer, or null.
        public static StringCollection GetFiles()
        {
            try
            {
                return Clipboard.ContainsFileDropList() ? Clipboard.GetFileDropList() : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /*
         * The copied HTML, or null. The clipboard's HTML format starts with a small header
         * ("Version:0.9 StartHTML:... StartFragment:...") and marks the part you actually
         * selected with <!--StartFragment--> and <!--EndFragment-->; only that part is returned.
         */
        public static string GetHtml()
        {
            try
            {
                if (!Clipboard.ContainsData(DataFormats.Html))
                {
                    return null;
                }
                object data = Clipboard.GetData(DataFormats.Html);
                string cfHtml = data as string;
                MemoryStream stream = data as MemoryStream;
                if (cfHtml == null && stream != null)
                {
                    cfHtml = Encoding.UTF8.GetString(stream.ToArray());
                }
                return cfHtml == null ? null : FixMojibake(ExtractFragment(cfHtml));
            }
            catch (Exception)
            {
                return null;
            }
        }

        // Clipboard data that holds raw bytes (a stream or a byte array) -> the bytes, or null.
        private static byte[] ToBytes(object data)
        {
            byte[] bytes = data as byte[];
            if (bytes != null)
            {
                return bytes;
            }
            MemoryStream memory = data as MemoryStream;
            if (memory != null)
            {
                return memory.ToArray();
            }
            Stream stream = data as Stream;
            if (stream != null)
            {
                MemoryStream copy = new MemoryStream();
                stream.CopyTo(copy);
                return copy.ToArray();
            }
            return null;
        }

        // Cuts the selected part (between StartFragment and EndFragment) out of the clipboard HTML.
        private static string ExtractFragment(string cfHtml)
        {
            const string StartMarker = "<!--StartFragment-->";
            const string EndMarker = "<!--EndFragment-->";
            int start = cfHtml.IndexOf(StartMarker, StringComparison.OrdinalIgnoreCase);
            int end = cfHtml.IndexOf(EndMarker, StringComparison.OrdinalIgnoreCase);
            if (start >= 0 && end > start)
            {
                return cfHtml.Substring(start + StartMarker.Length, end - start - StartMarker.Length);
            }
            int firstTag = cfHtml.IndexOf('<');
            return firstTag >= 0 ? cfHtml.Substring(firstTag) : cfHtml;
        }

        /*
         * The clipboard's HTML is UTF-8, but it sometimes gets decoded as the old Windows
         * code page 1252, which turns a curly apostrophe into three junk characters (the
         * "mojibake" you sometimes see on web pages). If the text has those telltale junk
         * characters, undo the wrong decoding: turn it back into the original bytes and decode
         * them as UTF-8. If that fails, the text was fine all along.
         */
        private static string FixMojibake(string s)
        {
            // \u00C3 and \u00E2\u20AC are how the first bytes of common UTF-8 letters look when misread as 1252
            if (s.IndexOf('\u00C3') < 0 && s.IndexOf("\u00E2\u20AC", StringComparison.Ordinal) < 0)
            {
                return s;
            }
            try
            {
                byte[] original = Encoding.GetEncoding(1252).GetBytes(s);
                return new UTF8Encoding(false, true).GetString(original);   // true: fail on invalid UTF-8
            }
            catch (Exception)
            {
                return s;
            }
        }
    }
}
