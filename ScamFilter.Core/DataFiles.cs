using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ScamFilter
{
    // File helpers shared by the project.
    public static class DataFiles
    {
        // The invisible "byte order mark" some editors (like Windows Notepad) put at the start of a file.
        private const char ByteOrderMark = (char) 0xFEFF;

        // Opens a text file for reading as UTF-8 (so emoji and accented letters come through
        // correctly on every computer). The caller must Close() it.
        public static StreamReader OpenReader(string path)
        {
            if (!File.Exists(path))
            {
                // Show the full path, so it's obvious when the program looked in the wrong folder.
                throw new FileNotFoundException("File not found: " + Path.GetFullPath(path));
            }
            return new StreamReader(path, Encoding.UTF8);
        }

        // Removes a byte order mark from the start of a line, if there is one.
        public static string StripBom(string line)
        {
            if (line != null && line.Length > 0 && line[0] == ByteOrderMark)
            {
                return line.Substring(1);
            }
            return line;
        }

        /*
         * Reads a simple list file: one entry per line.
         * Blank lines and lines starting with # (comments) are skipped, and a note after the
         * entry is dropped: "4045550142  # Mom" reads as "4045550142". (A note starts with a
         * space and then #; entries never contain spaces, so that can't cut one short.)
         * A missing file gives an empty list, so optional lists can simply not exist.
         */
        public static List<string> ReadList(string path)
        {
            List<string> entries = new List<string>();
            if (!File.Exists(path))
            {
                return entries;
            }
            StreamReader reader = OpenReader(path);
            string line = reader.ReadLine();
            bool first = true;
            while (line != null)
            {
                if (first)
                {
                    line = StripBom(line);
                    first = false;
                }
                string trimmed = line.Trim();
                if (trimmed.Length > 0 && !trimmed.StartsWith('#'))
                {
                    int note = trimmed.IndexOf(" #", StringComparison.Ordinal);
                    entries.Add(note >= 0 ? trimmed.Substring(0, note).Trim() : trimmed);
                }
                line = reader.ReadLine();
            }
            reader.Close();
            return entries;
        }

        // Adds one line to the end of a text file (creating the file and its folder if needed).
        public static void AppendLine(string path, string line)
        {
            // Another ScamFilter window may be adding to the same file this very moment.
            SharedFiles.Retry(() => AppendLineOnce(path, line));
        }

        /*
         * Opening the file with FileShare.None also locks it: while one window is adding its
         * line, another window's attempt fails with an IOException, and Retry tries it again a
         * moment later. So lines from two windows never get mixed together.
         */
        private static void AppendLineOnce(string path, string line)
        {
            string folder = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }
            FileStream file = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try
            {
                // If the file doesn't already end with a newline, add one first so lines don't merge.
                bool needsNewline = false;
                if (file.Length > 0)
                {
                    file.Seek(-1, SeekOrigin.End);
                    needsNewline = file.ReadByte() != '\n';
                }
                file.Seek(0, SeekOrigin.End);
                byte[] bytes = new UTF8Encoding(false).GetBytes((needsNewline ? "\n" : "") + line + "\n");
                file.Write(bytes, 0, bytes.Length);
                file.Flush();
            }
            finally
            {
                file.Close();
                file.Dispose();
            }
        }
    }
}
