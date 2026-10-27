using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace ScamFilter
{
    /*
     * Several copies of ScamFilter can be open at once (two windows for two people, or the same
     * account twice). They all use the same data folder, so two of them could try to change the
     * same file at the same moment. This class has the two tools that keep that safe.
     *
     * ============================================================================
     *  1. A LOCK FILE: "only one window at a time"
     * ============================================================================
     * To lock, a window opens a small file (like accounts.lock) with FileShare.None, which tells
     * Windows "nobody else may open this file while I have it open". A second window that tries
     * gets an IOException, waits a moment, and tries again. Closing the file unlocks it. If a
     * window crashes, Windows closes its files, so a lock can never be left stuck.
     *
     * (The same idea as Java's FileChannel.lock(). It's used instead of a named Mutex because a
     * Mutex belongs to the thread that took it, and the app's code moves between threads at
     * every "await".)
     *
     * Typical use, read-change-write:
     *
     *     FileLock held = FileLock.Acquire(lockPath, TimeSpan.FromSeconds(10));
     *     try
     *     {
     *         ...read the file, change it, write it back...
     *     }
     *     finally
     *     {
     *         held.Release();
     *     }
     *
     * ============================================================================
     *  2. WRITING A WHOLE FILE SAFELY
     * ============================================================================
     * WriteAtomically writes to a temporary file first, then swaps it in with File.Move. Readers
     * see the old file or the new one, never half of each. The temporary file's name includes
     * this program's process ID, so two windows never write into the same temporary file. If
     * the swap fails because another window is reading the file that very moment, it waits a
     * moment and tries again.
     */
    public sealed class FileLock
    {
        private FileStream stream;

        private FileLock(FileStream stream)
        {
            this.stream = stream;
        }

        /*
         * Takes the lock, waiting up to `wait` for another window to let go. Returns null if it
         * couldn't (the other window is busy for a long time); callers decide what that means.
         */
        public static FileLock Acquire(string lockPath, TimeSpan wait)
        {
            string folder = Path.GetDirectoryName(lockPath);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }
            Stopwatch clock = Stopwatch.StartNew();
            while (true)
            {
                FileLock held = TryAcquire(lockPath);
                if (held != null)
                {
                    return held;
                }
                if (clock.Elapsed >= wait)
                {
                    return null;
                }
                Thread.Sleep(50);
            }
        }

        // Takes the lock only if nobody has it right now; otherwise returns null straight away.
        public static FileLock TryAcquire(string lockPath)
        {
            try
            {
                string folder = Path.GetDirectoryName(lockPath);
                if (!string.IsNullOrEmpty(folder))
                {
                    Directory.CreateDirectory(folder);
                }
                FileStream s = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                return new FileLock(s);
            }
            catch (IOException)
            {
                return null;   // another window has it
            }
            catch (UnauthorizedAccessException)
            {
                return null;   // Windows sometimes reports a file being closed this way
            }
        }

        // Unlocks: closes the lock file so another window can take it.
        public void Release()
        {
            if (stream != null)
            {
                stream.Close();
                stream.Dispose();
                stream = null;
            }
        }
    }

    // Whole-file writes and retries for files several windows share (see the comment at the top).
    public static class SharedFiles
    {
        // Writes a whole file so that nothing ever reads half of it (see the class comment above).
        public static void WriteAtomically(string path, byte[] contents)
        {
            string folder = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }
            string temporary = path + "." + Environment.ProcessId + ".tmp";
            File.WriteAllBytes(temporary, contents);
            MoveWithRetry(temporary, path);
        }

        // The same, for text (saved as UTF-8 without a byte-order mark).
        public static void WriteAtomically(string path, string text)
        {
            WriteAtomically(path, new UTF8Encoding(false).GetBytes(text));
        }

        // File.Move(from, to, overwrite), trying again for up to 2 seconds if `to` is in use.
        public static void MoveWithRetry(string from, string to)
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    File.Move(from, to, true);
                    return;
                }
                catch (Exception e) when ((e is IOException || e is UnauthorizedAccessException) && attempt < 40)
                {
                    Thread.Sleep(50);
                }
            }
        }

        /*
         * Runs `action`, trying again for up to 2 seconds if it fails because a file is in use
         * by another window (for example, two windows adding a line to the same file at once).
         */
        public static void Retry(Action action)
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    action();
                    return;
                }
                catch (IOException) when (attempt < 40)
                {
                    Thread.Sleep(50);
                }
            }
        }
    }
}
