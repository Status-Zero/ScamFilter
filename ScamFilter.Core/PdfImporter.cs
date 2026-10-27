using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor;
using UglyToad.PdfPig.Exceptions;

namespace ScamFilter
{
    /*
     * Turns a PDF into a MessageRecord: the connector for documents. Scammers like PDFs: a fake
     * invoice ("your subscription renewed for $399, call to cancel"), a fake account statement,
     * or a "document shared with you" often arrives as a PDF attachment, because a PDF looks
     * official and some mail filters don't read inside them.
     *
     * Nothing AI here. A PDF is a description of each page: "put these letters, in this font, at
     * these positions; put this picture here; this rectangle is a link to this address". PdfPig
     * (a library) reads that description and gives back the letters, in order, and the links.
     *
     * Two kinds of page:
     *   TEXT PAGES      made by a program (Word, a billing system). The letters are really there,
     *                   so the text comes out exactly, and so do the links' REAL targets: the
     *                   same best clue as in an email.
     *   SCANNED PAGES   a picture of a page (a scan, or a screenshot saved as a PDF). There are no
     *                   letters to read, just a picture, so those pages are listed in
     *                   Result.ScannedPages and the app reads them with OCR, like a screenshot.
     *
     * The record is an "email": a PDF reads like a letter or a bill, the kind of message the
     * model learned from emails. It has no sender (a file doesn't have one); missing information
     * only means fewer clues, never a clue of its own (see MetadataFeatures).
     *
     * Text drawn invisibly is kept on purpose: in a scanned PDF that's the "text layer" added so
     * the page can be searched, and it's the same words the picture shows.
     */
    public static class PdfImporter
    {
        // Only the first pages are read. A scam is never 50 pages long, and a huge PDF would
        // take a long time for nothing.
        public const int MaxPages = 20;

        // At most this much text is kept (about 6 pages of dense text).
        public const int MaxTextLength = 20000;

        // A page with fewer letters than this AND a picture on it counts as a scanned page.
        // (A scanned page can still have a few real letters, like a page number.)
        private const int MinLettersForTextPage = 20;

        // What came out of a PDF.
        public class Result
        {
            public MessageRecord Record = new MessageRecord();      // the text and links of the text pages
            public int PageCount = 0;                                // pages in the whole PDF
            public List<int> ScannedPages = new List<int>();         // page numbers (1 = first page) to read with OCR

            // True if the PDF had more pages than were read.
            public bool Truncated
            {
                get { return PageCount > MaxPages; }
            }
        }

        // Thrown when the PDF can't be opened without its password.
        public class PasswordProtectedException : Exception
        {
            public PasswordProtectedException()
                : base("This PDF is protected with a password, so ScamFilter can't read it. Open it, then take a "
                       + "screenshot of the pages and paste that instead.")
            {
            }
        }

        /*
         * Does this look like a PDF? Every PDF starts with "%PDF-" (a few programs put some junk
         * in front, so the first 1024 bytes are searched).
         */
        public static bool LooksLikePdf(byte[] start)
        {
            if (start == null)
            {
                return false;
            }
            int end = Math.Min(start.Length, 1024) - 5;
            for (int i = 0; i <= end; i++)
            {
                if (start[i] == '%' && start[i + 1] == 'P' && start[i + 2] == 'D' && start[i + 3] == 'F' && start[i + 4] == '-')
                {
                    return true;
                }
            }
            return false;
        }

        // Reads a PDF file from disk.
        public static Result Load(string path)
        {
            return Load(File.ReadAllBytes(path));
        }

        // Reads a PDF given as its bytes. Throws PasswordProtectedException if it needs a password.
        public static Result Load(byte[] bytes)
        {
            PdfDocument document;
            try
            {
                document = PdfDocument.Open(bytes);
            }
            catch (PdfDocumentEncryptedException)
            {
                // Some PDFs are "encrypted" with an empty password just to stop copying; PdfPig
                // opens those by itself. This one needs a real password.
                throw new PasswordProtectedException();
            }
            try
            {
                Result result = new Result();
                result.Record.Type = "email";
                result.PageCount = document.NumberOfPages;
                StringBuilder text = new StringBuilder();
                int lastPage = Math.Min(document.NumberOfPages, MaxPages);
                for (int number = 1; number <= lastPage && text.Length < MaxTextLength; number++)
                {
                    Page page = document.GetPage(number);
                    if (page.Letters.Count < MinLettersForTextPage && page.GetImages().Any())
                    {
                        result.ScannedPages.Add(number);
                    }
                    else
                    {
                        // The letters in reading order, with line breaks where the lines end.
                        string pageText = ContentOrderTextExtractor.GetText(page).Trim();
                        if (pageText.Length > 0)
                        {
                            text.Append(pageText).Append("\n\n");
                        }
                    }
                    AddLinks(page, result.Record.Urls);
                }
                string all = text.ToString().Trim();
                result.Record.BodyText = all.Length > MaxTextLength ? all.Substring(0, MaxTextLength) : all;
                return result;
            }
            finally
            {
                document.Dispose();
            }
        }

        /*
         * The page's links: each clickable rectangle's real target, and the text shown inside the
         * rectangle (often the address it pretends to go to). Only web links are kept, the same as
         * for emails (EmlImporter).
         */
        private static void AddLinks(Page page, List<MessageRecord.UrlRef> urls)
        {
            foreach (Hyperlink link in page.GetHyperlinks())
            {
                string target = (link.Uri ?? "").Trim();
                if (!target.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                string shown = (link.Text ?? "").Trim();
                bool already = urls.Any(u => u.Href == target && u.Display == shown);
                if (!already)
                {
                    urls.Add(new MessageRecord.UrlRef(shown, target));
                }
            }
        }
    }
}
