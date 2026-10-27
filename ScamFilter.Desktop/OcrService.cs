using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Storage;
using Windows.Storage.Streams;

namespace ScamFilter.Desktop
{
    /*
     * Reads the text out of pictures (screenshots, photos, scanned PDF pages), using the OCR
     * (optical character recognition) built into Windows 10 and 11. Nothing is uploaded:
     * Windows does it on this PC.
     *
     * The result goes into a MessageRecord with Channel = "ocr", which tells the model that
     * character tricks (paypa1 vs paypal) can't be trusted in this text, because OCR makes
     * exactly those mistakes on its own (see MetadataFeatures).
     *
     * ============================================================================
     *  PICTURE FORMATS
     * ============================================================================
     * Pictures are opened with WPF's decoder, which handles PNG, JPEG, GIF, BMP, TIFF, ICO and
     * JPEG XR, plus anything else Windows has a decoder for. If WPF can't open one, Windows'
     * own decoder (the one the Photos app uses) gets a try: that's how WebP, HEIC (iPhone
     * photos) and AVIF open, when Windows has their free extensions from the Microsoft Store.
     *
     * Before OCR, every picture is "prepared":
     *   - turned upright: a phone photo is often stored sideways with a note saying which way
     *     is up (its EXIF "orientation"), and OCR can't read sideways text.
     *   - see-through parts are put on a white background. Otherwise they turn black, and dark
     *     text on black disappears.
     *   - small pictures are enlarged 2x. Windows' OCR misses small text (a cropped desktop
     *     screenshot at normal size is ~11 pixels tall per letter); bigger letters read better.
     *
     * ============================================================================
     *  PDF PAGES
     * ============================================================================
     * Most PDFs have real text, which PdfImporter (in ScamFilter.Core) reads exactly. A scanned
     * page is only a picture, so it's drawn ("rendered") to a picture by Windows' own PDF
     * reader (Windows.Data.Pdf, the one Edge uses) and read with OCR like a screenshot.
     *
     * The Windows.* namespaces are Windows' own APIs ("WinRT"). They're available because the
     * project targets a specific Windows version (see ScamFilter.Desktop.csproj). Most of them
     * are "async": they return right away and finish later, so the window never freezes while
     * a big picture is being read. "await" waits for the result without blocking the window.
     */
    public static class OcrService
    {
        // Pictures whose longest side is shorter than this get enlarged 2x before OCR.
        private const int SmallImagePixels = 1600;

        // A multi-page TIFF (a fax or a scan) is read up to this many pages.
        private const int MaxTiffPages = 10;

        // Scanned PDF pages are drawn at about this many dots per inch: sharp enough for OCR,
        // small enough to be quick.
        private const double PdfDotsPerInch = 200;

        // The picture file extensions ScamFilter offers to open (WPF or Windows decides in the end).
        private static readonly string[] ImageExtensions =
        {
            ".png", ".jpg", ".jpeg", ".jpe", ".jfif", ".bmp", ".dib", ".gif", ".tif", ".tiff",
            ".ico", ".jxr", ".wdp", ".hdp", ".webp", ".heic", ".heif", ".avif"
        };

        // For the Upload a file window: "*.png;*.jpg;..."
        public static string ImageFilePattern
        {
            get { return "*" + string.Join(";*", ImageExtensions); }
        }

        // Is this a picture file (by its extension)?
        public static bool IsImageFile(string path)
        {
            return Array.IndexOf(ImageExtensions, Path.GetExtension(path).ToLowerInvariant()) >= 0;
        }

        /*
         * Does this look like a picture, whatever the file is called? Every picture format starts
         * with its own fixed bytes (its "signature"), so a photo saved with the wrong extension, or
         * none, can still be recognized.
         */
        public static bool LooksLikeImage(byte[] b)
        {
            if (b == null || b.Length < 12)
            {
                return false;
            }
            bool png = b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G';
            bool jpeg = b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF;
            bool gif = b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8';
            bool bmp = b[0] == 'B' && b[1] == 'M';
            bool tiff = (b[0] == 'I' && b[1] == 'I' && b[2] == 42 && b[3] == 0) || (b[0] == 'M' && b[1] == 'M' && b[2] == 0 && b[3] == 42);
            bool webp = b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F' && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P';
            // HEIC and AVIF are "ISO media" files: bytes 4-7 say "ftyp"
            bool isoMedia = b[4] == 'f' && b[5] == 't' && b[6] == 'y' && b[7] == 'p';
            return png || jpeg || gif || bmp || tiff || webp || isoMedia;
        }

        // Reads the text in a picture file.
        public static async Task<string> ReadImageFileAsync(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            try
            {
                return await ReadImageBytesAsync(bytes);
            }
            catch (NotSupportedException)
            {
                throw new NotSupportedException(MissingCodecAdvice(Path.GetExtension(path).ToLowerInvariant()));
            }
        }

        /*
         * Reads the text in a picture given as file bytes (a PNG from the clipboard, an email's
         * picture, a scanned PDF page). dropAlpha: see ReadBitmapAsync.
         */
        public static async Task<string> ReadImageBytesAsync(byte[] bytes, bool dropAlpha = false)
        {
            List<BitmapSource> pages = await DecodeAsync(bytes);
            StringBuilder text = new StringBuilder();
            foreach (BitmapSource page in pages)
            {
                string pageText = await ReadBitmapAsync(page, dropAlpha);
                if (pageText.Length > 0)
                {
                    text.AppendLine(pageText).AppendLine();
                }
            }
            return text.ToString().Trim();
        }

        /*
         * Reads a picture already in memory. dropAlpha = true for pictures from the clipboard's
         * older Bitmap format, which often says every pixel is fully see-through even though
         * the colors are fine; ignoring transparency there gives the real picture.
         */
        public static async Task<string> ReadBitmapAsync(BitmapSource image, bool dropAlpha)
        {
            BitmapSource source = dropAlpha ? new FormatConvertedBitmap(image, PixelFormats.Bgr32, null, 0) : image;
            BitmapSource prepared = Prepare(source);
            string temp = Path.Combine(Path.GetTempPath(), "scamfilter_" + Guid.NewGuid().ToString("N") + ".png");
            PngBitmapEncoder encoder = new PngBitmapEncoder();
            encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(prepared));   // WPF's, not Windows'
            FileStream output = File.Create(temp);
            encoder.Save(output);
            output.Close();
            try
            {
                return await RecognizeFileAsync(temp);
            }
            finally
            {
                File.Delete(temp);
            }
        }

        // ------------------------------------------------------------------
        // Opening pictures
        // ------------------------------------------------------------------

        /*
         * Picture file bytes -> the picture, upright. Usually one picture; every page of a
         * multi-page TIFF. Throws NotSupportedException if neither WPF nor Windows can open it.
         * (Both WPF and Windows have classes named BitmapDecoder and BitmapFrame, so they're
         * written out in full.)
         */
        private static async Task<List<BitmapSource>> DecodeAsync(byte[] bytes)
        {
            try
            {
                return DecodeWithWpf(bytes);
            }
            catch (Exception wpfError) when (wpfError is NotSupportedException || wpfError is FileFormatException
                                             || wpfError is ArgumentException || wpfError is IOException
                                             || wpfError is System.Runtime.InteropServices.COMException)
            {
                // Not a format WPF knows: let Windows' own decoder turn it into a PNG first.
                byte[] png;
                try
                {
                    png = await ConvertToPngWithWindowsAsync(bytes);
                }
                catch (Exception)
                {
                    throw new NotSupportedException("ScamFilter couldn't open this picture.", wpfError);
                }
                return DecodeWithWpf(png);
            }
        }

        // Decodes with WPF: the first frame (a GIF's first frame), or each page of a TIFF.
        private static List<BitmapSource> DecodeWithWpf(byte[] bytes)
        {
            MemoryStream stream = new MemoryStream(bytes);
            System.Windows.Media.Imaging.BitmapDecoder decoder = System.Windows.Media.Imaging.BitmapDecoder.Create(stream,
                BitmapCreateOptions.PreservePixelFormat | BitmapCreateOptions.IgnoreColorProfile, BitmapCacheOption.OnLoad);
            int count = decoder is TiffBitmapDecoder ? Math.Min(decoder.Frames.Count, MaxTiffPages) : 1;
            List<BitmapSource> pages = new List<BitmapSource>();
            for (int i = 0; i < count; i++)
            {
                BitmapSource upright = Upright(decoder.Frames[i]);
                upright.Freeze();
                pages.Add(upright);
            }
            stream.Close();
            return pages;
        }

        /*
         * Turns a photo upright, using its EXIF "orientation" note (tag 274):
         *   1 upright           3 upside down       6 needs turning 90 degrees clockwise
         *   8 needs 270 (90 the other way)          2, 4, 5, 7: the same, mirrored
         * Screenshots don't have the note, so they're returned as they are.
         */
        private static BitmapSource Upright(System.Windows.Media.Imaging.BitmapFrame frame)
        {
            int orientation = 1;
            try
            {
                BitmapMetadata metadata = frame.Metadata as BitmapMetadata;
                if (metadata != null)
                {
                    // JPEG keeps EXIF in its "APP1" block; TIFF keeps it in the main block.
                    foreach (string query in new string[] { "/app1/ifd/{ushort=274}", "/ifd/{ushort=274}" })
                    {
                        if (metadata.ContainsQuery(query))
                        {
                            object value = metadata.GetQuery(query);
                            if (value is ushort)
                            {
                                orientation = (ushort) value;
                            }
                            break;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // unreadable metadata: treat it as upright
            }
            if (orientation < 2 || orientation > 8)
            {
                return frame;
            }
            TransformGroup turn = new TransformGroup();
            if (orientation == 2 || orientation == 4 || orientation == 5 || orientation == 7)
            {
                turn.Children.Add(new ScaleTransform(-1, 1));   // mirrored: flip it back first
            }
            int degrees = orientation == 3 || orientation == 4 ? 180
                : orientation == 5 || orientation == 6 ? 90
                : orientation == 7 || orientation == 8 ? 270 : 0;
            if (degrees != 0)
            {
                turn.Children.Add(new RotateTransform(degrees));
            }
            return new TransformedBitmap(frame, turn);
        }

        /*
         * Windows' own decoder (the Photos app's): picture bytes in, PNG bytes out. It can open
         * whatever Windows has an extension for (WebP, HEIC, AVIF), and it turns photos upright
         * by itself (RespectExifOrientation).
         */
        private static async Task<byte[]> ConvertToPngWithWindowsAsync(byte[] bytes)
        {
            InMemoryRandomAccessStream input = new InMemoryRandomAccessStream();
            InMemoryRandomAccessStream output = new InMemoryRandomAccessStream();
            try
            {
                DataWriter writer = new DataWriter(input);
                writer.WriteBytes(bytes);
                await writer.StoreAsync();
                writer.DetachStream();
                writer.Dispose();
                input.Seek(0);

                Windows.Graphics.Imaging.BitmapDecoder decoder = await Windows.Graphics.Imaging.BitmapDecoder.CreateAsync(input);
                SoftwareBitmap bitmap = await decoder.GetSoftwareBitmapAsync(
                    BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, new BitmapTransform(),
                    ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage);
                Windows.Graphics.Imaging.BitmapEncoder encoder = await Windows.Graphics.Imaging.BitmapEncoder.CreateAsync(
                    Windows.Graphics.Imaging.BitmapEncoder.PngEncoderId, output);
                encoder.SetSoftwareBitmap(bitmap);
                await encoder.FlushAsync();
                bitmap.Dispose();
                return await ReadAllAsync(output);
            }
            finally
            {
                input.Dispose();
                output.Dispose();
            }
        }

        // Every byte of an in-memory Windows stream.
        private static async Task<byte[]> ReadAllAsync(IRandomAccessStream stream)
        {
            byte[] bytes = new byte[stream.Size];
            DataReader reader = new DataReader(stream.GetInputStreamAt(0));
            try
            {
                await reader.LoadAsync((uint) stream.Size);
                reader.ReadBytes(bytes);
            }
            finally
            {
                reader.Dispose();
            }
            return bytes;
        }

        // What to tell someone whose picture Windows can't open, by its file extension.
        private static string MissingCodecAdvice(string extension)
        {
            if (extension == ".heic" || extension == ".heif")
            {
                return "Windows can't open HEIC photos (the iPhone's format) until the free \"HEIF Image Extensions\" "
                    + "is installed from the Microsoft Store. Or save the photo as a JPG and upload that.";
            }
            if (extension == ".webp")
            {
                return "Windows can't open WebP pictures until the free \"Webp Image Extensions\" is installed from the "
                    + "Microsoft Store. Or take a screenshot of the picture and paste that.";
            }
            if (extension == ".avif")
            {
                return "Windows can't open AVIF pictures until the free \"AV1 Video Extension\" is installed from the "
                    + "Microsoft Store. Or take a screenshot of the picture and paste that.";
            }
            return "This file isn't a picture Windows can open. Take a screenshot of it and paste that instead.";
        }

        // ------------------------------------------------------------------
        // Scanned PDF pages
        // ------------------------------------------------------------------

        /*
         * Reads the text on some pages of a PDF with OCR (page numbers start at 1; null means
         * every page up to PdfImporter.MaxPages). progress is told which page it's on.
         */
        public static async Task<string> ReadPdfPagesAsync(string path, IList<int> pageNumbers, Action<string> progress)
        {
            StorageFile file = await StorageFile.GetFileFromPathAsync(Path.GetFullPath(path));
            Windows.Data.Pdf.PdfDocument pdf;
            try
            {
                pdf = await Windows.Data.Pdf.PdfDocument.LoadFromFileAsync(file);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Windows couldn't open this PDF (" + ex.Message.Trim() + ").", ex);
            }
            List<int> pages = new List<int>();
            if (pageNumbers != null)
            {
                pages.AddRange(pageNumbers);
            }
            else
            {
                for (int number = 1; number <= Math.Min((int) pdf.PageCount, PdfImporter.MaxPages); number++)
                {
                    pages.Add(number);
                }
            }

            StringBuilder text = new StringBuilder();
            for (int i = 0; i < pages.Count; i++)
            {
                int number = pages[i];
                if (number < 1 || number > pdf.PageCount)
                {
                    continue;
                }
                if (progress != null)
                {
                    progress(pages.Count == 1 ? "Reading the scanned page..." : "Reading scanned page " + (i + 1) + " of " + pages.Count + "...");
                }
                Windows.Data.Pdf.PdfPage page = pdf.GetPage((uint) (number - 1));
                try
                {
                    byte[] png = await RenderPageAsync(page);
                    string pageText = await ReadImageBytesAsync(png);
                    if (pageText.Length > 0)
                    {
                        text.AppendLine(pageText).AppendLine();
                    }
                }
                finally
                {
                    page.Dispose();
                }
            }
            return text.ToString().Trim();
        }

        // Draws one PDF page as a PNG picture, at about PdfDotsPerInch.
        private static async Task<byte[]> RenderPageAsync(Windows.Data.Pdf.PdfPage page)
        {
            Windows.Data.Pdf.PdfPageRenderOptions options = new Windows.Data.Pdf.PdfPageRenderOptions();
            // The page's size is in 1/96ths of an inch; the height follows from the width.
            double widthInches = page.Size.Width / 96.0;
            options.DestinationWidth = (uint) Math.Max(800, Math.Min(4000, widthInches * PdfDotsPerInch));
            options.BitmapEncoderId = Windows.Graphics.Imaging.BitmapEncoder.PngEncoderId;
            InMemoryRandomAccessStream stream = new InMemoryRandomAccessStream();
            try
            {
                await page.RenderToStreamAsync(stream, options);
                return await ReadAllAsync(stream);
            }
            finally
            {
                stream.Dispose();
            }
        }

        // ------------------------------------------------------------------
        // Preparing a picture and running OCR
        // ------------------------------------------------------------------

        // Draws the picture onto white (and 2x bigger if it's small). See the class comment.
        private static BitmapSource Prepare(BitmapSource image)
        {
            int width = image.PixelWidth;
            int height = image.PixelHeight;
            int scale = Math.Max(width, height) < SmallImagePixels ? 2 : 1;
            int outWidth = width * scale;
            int outHeight = height * scale;

            DrawingVisual visual = new DrawingVisual();
            RenderOptions.SetBitmapScalingMode(visual, BitmapScalingMode.HighQuality);
            DrawingContext dc = visual.RenderOpen();
            dc.DrawRectangle(Brushes.White, null, new Rect(0, 0, outWidth, outHeight));
            dc.DrawImage(image, new Rect(0, 0, outWidth, outHeight));
            dc.Close();

            RenderTargetBitmap result = new RenderTargetBitmap(outWidth, outHeight, 96, 96, PixelFormats.Pbgra32);
            result.Render(visual);
            result.Freeze();
            return result;
        }

        // Runs Windows' OCR on a prepared PNG file and returns the text, one line per line found.
        private static async Task<string> RecognizeFileAsync(string path)
        {
            // Uses the languages set up in Windows (Settings > Time & language > Language & region).
            OcrEngine engine = OcrEngine.TryCreateFromUserProfileLanguages();
            if (engine == null)
            {
                throw new InvalidOperationException("Windows doesn't have a text-recognition language installed. "
                    + "Add one in Settings > Time & language > Language & region, then try again.");
            }

            StorageFile file = await StorageFile.GetFileFromPathAsync(Path.GetFullPath(path));
            IRandomAccessStream stream = await file.OpenAsync(FileAccessMode.Read);
            try
            {
                // (WPF also has a class called BitmapDecoder, so this one is written out in full.)
                Windows.Graphics.Imaging.BitmapDecoder decoder = await Windows.Graphics.Imaging.BitmapDecoder.CreateAsync(stream);

                // OCR has a maximum image size. Shrink anything bigger, keeping its shape.
                BitmapTransform transform = new BitmapTransform();
                uint max = OcrEngine.MaxImageDimension;
                uint width = decoder.PixelWidth;
                uint height = decoder.PixelHeight;
                if (width > max || height > max)
                {
                    double shrink = Math.Min((double) max / width, (double) max / height);
                    transform.ScaledWidth = (uint) (width * shrink);
                    transform.ScaledHeight = (uint) (height * shrink);
                    transform.InterpolationMode = BitmapInterpolationMode.Fant;
                }

                SoftwareBitmap bitmap = await decoder.GetSoftwareBitmapAsync(
                    BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, transform,
                    ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage);
                OcrResult result = await engine.RecognizeAsync(bitmap);
                bitmap.Dispose();

                StringBuilder text = new StringBuilder();
                foreach (OcrLine line in result.Lines)
                {
                    text.AppendLine(line.Text);
                }
                return text.ToString().Trim();
            }
            finally
            {
                stream.Dispose();
            }
        }

        // ------------------------------------------------------------------
        // Finding the sender in a screenshot
        // ------------------------------------------------------------------

        // A line that's only a phone number: digits with optional + ( ) - . and spaces
        private static readonly Regex PhoneLine = new Regex(@"^\+?[0-9\s().-]{7,22}$");

        // A line that's only a business short code, like 24273
        private static readonly Regex ShortCodeLine = new Regex(@"^[0-9]{5,6}$");

        /*
         * Messaging apps show who the conversation is with at the top of the screen. If one of
         * the first few lines is just a phone number, short code, or email address, it's
         * probably the sender. Returns "" if nothing looks like one.
         */
        public static string GuessSender(string ocrText)
        {
            string[] lines = ocrText.Split('\n');
            for (int i = 0; i < lines.Length && i < 6; i++)
            {
                // Drop leading symbols like the back arrow "<" that OCR picks up from the title bar
                string line = Regex.Replace(lines[i].Trim(), @"^[^0-9A-Za-z+(]+", "").Trim();
                if (line.Length == 0)
                {
                    continue;
                }
                int digits = MetadataFeatures.DigitsOnly(line).Length;
                if (PhoneLine.IsMatch(line) && digits >= 7 && digits <= 15)
                {
                    return line;
                }
                if (ShortCodeLine.IsMatch(line))
                {
                    return line;
                }
                Match email = UrlAnalyzer.Email.Match(line);
                if (email.Success && line.Length <= email.Length + 4)
                {
                    return email.Value;
                }
            }
            return "";
        }
    }
}
