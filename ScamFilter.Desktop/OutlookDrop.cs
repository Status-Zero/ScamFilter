using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using ComTypes = System.Runtime.InteropServices.ComTypes;

namespace ScamFilter.Desktop
{
    /*
     * Reads an email dragged straight out of classic Outlook (or one of its attachments, like a
     * PDF invoice or a picture: those arrive the same way, as a plain stream of bytes).
     *
     * Dragging a FILE from File Explorer hands over a path. Dragging an EMAIL from Outlook
     * doesn't: the email isn't a file anywhere yet. Outlook offers a "virtual file" instead:
     *
     *   FileGroupDescriptorW   the name(s) the file(s) would have ("Your account.msg")
     *   FileContents           the file's bytes, produced on request
     *
     * For an email, Outlook hands FileContents over as an "IStorage": the compound-file
     * container that .msg files are made of, still open inside Outlook. To get plain bytes,
     * this code creates an empty compound file in memory, has Windows copy Outlook's storage
     * into it, then reads the memory out. That's all COM (Windows' old component system),
     * which is why there are interface declarations and DllImports below. You don't need to
     * follow the details: the result is the same bytes as a saved .msg file.
     *
     * If anything goes wrong, ReadFirstFile returns null and the app asks the user to drag the
     * email to the desktop first and drop that file instead.
     *
     * THE NEW OUTLOOK is different: it's built on the Chromium browser engine (like Outlook on
     * the web), and hands a dragged email over as an ordinary .eml FILE, but only to a program
     * that says it can wait for it (see AsyncDrop.cs). Older versions of the new Outlook can't
     * hand emails over by dragging at all; IsFromWebOutlook recognizes those drags, so the app
     * can say what to do instead.
     */
    public static class OutlookDrop
    {
        // Is an email being dragged straight out of Outlook? (It arrives as a "virtual file": the
        // email's contents, with no file on disk.)
        public static bool HasVirtualFile(System.Windows.IDataObject data)
        {
            try
            {
                return data.GetDataPresent("FileGroupDescriptorW") || data.GetDataPresent("FileGroupDescriptor");
            }
            catch (Exception)
            {
                return false;
            }
        }

        // The formats Chromium-based programs (the new Outlook, Outlook on the web in Edge or
        // Chrome) add to everything they drag.
        private static readonly string[] ChromiumFormats = { "Chromium Web Custom MIME Data Format", "chromium/x-renderer-taint" };

        // Was this dragged out of a Chromium-based program, like the new Outlook?
        public static bool IsFromWebOutlook(System.Windows.IDataObject data)
        {
            try
            {
                foreach (string format in ChromiumFormats)
                {
                    if (data.GetDataPresent(format, false))
                    {
                        return true;
                    }
                }
            }
            catch (Exception)
            {
                // unreadable: treat as not
            }
            return false;
        }

        /*
         * A drag from a Chromium-based program with nothing ScamFilter can use: no file, no
         * virtual file, and no text (text would go to the text boxes). That's an email dragged
         * out of an older new Outlook, which can't hand emails to other programs.
         */
        public static bool IsUnreadableWebDrag(System.Windows.IDataObject data)
        {
            try
            {
                return IsFromWebOutlook(data)
                    && !data.GetDataPresent(System.Windows.DataFormats.FileDrop)
                    && !HasVirtualFile(data)
                    && !data.GetDataPresent(System.Windows.DataFormats.UnicodeText)
                    && !data.GetDataPresent(System.Windows.DataFormats.Html);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /*
         * The first dragged file's name. In FileGroupDescriptorW, a 4-byte count is followed by
         * one 592-byte FILEDESCRIPTORW per file, and the name is the last 520 bytes of that
         * (260 two-byte characters), starting 72 bytes in. So the first name starts at byte 76.
         */
        public static string FirstFileName(System.Windows.IDataObject data)
        {
            try
            {
                MemoryStream stream = data.GetData("FileGroupDescriptorW") as MemoryStream;
                if (stream == null)
                {
                    return "";
                }
                byte[] bytes = stream.ToArray();
                if (bytes.Length < 4 + 592)
                {
                    return "";
                }
                string name = Encoding.Unicode.GetString(bytes, 76, 520);
                int end = name.IndexOf('\0');
                return end >= 0 ? name.Substring(0, end) : name;
            }
            catch (Exception)
            {
                return "";
            }
        }

        // The first dragged virtual file's bytes, or null if they can't be read.
        public static byte[] ReadFirstFile(System.Windows.IDataObject data)
        {
            // 1. The simple way: works when the program offers the bytes directly.
            try
            {
                MemoryStream simple = data.GetData("FileContents") as MemoryStream;
                if (simple != null && simple.Length > 0)
                {
                    return simple.ToArray();
                }
            }
            catch (Exception)
            {
                // Outlook usually refuses this for emails; try the COM way below.
            }

            // 2. The COM way, asking for the first file (index 0) in any format Outlook offers.
            ComTypes.IDataObject com = data as ComTypes.IDataObject;
            if (com == null)
            {
                return null;
            }
            ComTypes.FORMATETC format = new ComTypes.FORMATETC();
            format.cfFormat = unchecked((short) System.Windows.DataFormats.GetDataFormat("FileContents").Id);
            format.dwAspect = ComTypes.DVASPECT.DVASPECT_CONTENT;
            format.lindex = 0;
            format.ptd = IntPtr.Zero;
            format.tymed = ComTypes.TYMED.TYMED_ISTORAGE | ComTypes.TYMED.TYMED_ISTREAM | ComTypes.TYMED.TYMED_HGLOBAL;

            ComTypes.STGMEDIUM medium;
            try
            {
                com.GetData(ref format, out medium);
            }
            catch (Exception)
            {
                return null;
            }
            try
            {
                if (medium.tymed == ComTypes.TYMED.TYMED_ISTORAGE)
                {
                    return ReadStorage(medium.unionmember);
                }
                if (medium.tymed == ComTypes.TYMED.TYMED_ISTREAM)
                {
                    return ReadStream(medium.unionmember);
                }
                if (medium.tymed == ComTypes.TYMED.TYMED_HGLOBAL)
                {
                    return ReadHGlobal(medium.unionmember);
                }
                return null;
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                ReleaseStgMedium(ref medium);
            }
        }

        // Copies an open IStorage into a new compound file in memory, then reads the memory.
        private static byte[] ReadStorage(IntPtr storagePointer)
        {
            IStorage source = (IStorage) Marshal.GetObjectForIUnknown(storagePointer);
            ILockBytes memory = null;
            IStorage copy = null;
            try
            {
                Marshal.ThrowExceptionForHR(CreateILockBytesOnHGlobal(IntPtr.Zero, true, out memory));
                const uint Create = 0x1000, ReadWrite = 0x2, ShareExclusive = 0x10;
                Marshal.ThrowExceptionForHR(StgCreateDocfileOnILockBytes(memory, Create | ReadWrite | ShareExclusive, 0, out copy));
                source.CopyTo(0, IntPtr.Zero, IntPtr.Zero, copy);
                copy.Commit(0);

                ComTypes.STATSTG stat;
                memory.Stat(out stat, 1);   // 1 = don't return the name
                byte[] bytes = new byte[stat.cbSize];
                int read;
                memory.ReadAt(0, bytes, bytes.Length, out read);
                return bytes;
            }
            finally
            {
                if (copy != null)
                {
                    Marshal.ReleaseComObject(copy);
                }
                if (memory != null)
                {
                    Marshal.ReleaseComObject(memory);
                }
                Marshal.ReleaseComObject(source);
            }
        }

        /*
         * Copies everything from a COM stream (how attachments, and some other programs' files,
         * are handed over) into a byte array. It reads until the stream runs out instead of
         * trusting the size the stream reports: a stream still being written (a file a program
         * is downloading as you drop it) can report 0.
         */
        private static byte[] ReadStream(IntPtr streamPointer)
        {
            ComTypes.IStream stream = (ComTypes.IStream) Marshal.GetObjectForIUnknown(streamPointer);
            IntPtr readCount = Marshal.AllocCoTaskMem(sizeof(int));
            try
            {
                try
                {
                    stream.Seek(0, 0, IntPtr.Zero);   // 0 = from the start; some programs hand it over at the end
                }
                catch (Exception)
                {
                    // a stream that can't seek starts at the beginning anyway
                }
                MemoryStream all = new MemoryStream();
                byte[] buffer = new byte[64 * 1024];
                while (true)
                {
                    Marshal.WriteInt32(readCount, 0);
                    stream.Read(buffer, buffer.Length, readCount);
                    int read = Marshal.ReadInt32(readCount);
                    if (read <= 0)
                    {
                        break;
                    }
                    all.Write(buffer, 0, read);
                }
                return all.ToArray();
            }
            finally
            {
                Marshal.FreeCoTaskMem(readCount);
                Marshal.ReleaseComObject(stream);
            }
        }

        // Copies a block of global memory (the other way Windows can hand over dragged data).
        private static byte[] ReadHGlobal(IntPtr handle)
        {
            IntPtr pointer = GlobalLock(handle);
            try
            {
                int size = (int) GlobalSize(handle).ToUInt64();
                byte[] bytes = new byte[size];
                Marshal.Copy(pointer, bytes, 0, size);
                return bytes;
            }
            finally
            {
                GlobalUnlock(handle);
            }
        }

        // ------------------------------------------------------------------
        // COM declarations. A COM interface is a fixed list of functions in a fixed order, so
        // every function up to the last one used must be listed, in order, even unused ones.
        // ------------------------------------------------------------------

        [ComImport, Guid("0000000B-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IStorage
        {
            void CreateStream();      // unused, listed to keep the order
            void OpenStream();
            void CreateStorage();
            void OpenStorage();
            void CopyTo(int ciidExclude, IntPtr rgiidExclude, IntPtr snbExclude, IStorage pstgDest);
            void MoveElementTo();
            void Commit(int grfCommitFlags);
        }

        [ComImport, Guid("0000000A-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface ILockBytes
        {
            void ReadAt(long ulOffset, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] pv, int cb, out int pcbRead);
            void WriteAt();           // unused, listed to keep the order
            void Flush();
            void SetSize();
            void LockRegion();
            void UnlockRegion();
            void Stat(out ComTypes.STATSTG pstatstg, int grfStatFlag);
        }

        [DllImport("ole32.dll")]
        private static extern int CreateILockBytesOnHGlobal(IntPtr hGlobal, bool fDeleteOnRelease, out ILockBytes ppLkbyt);

        [DllImport("ole32.dll")]
        private static extern int StgCreateDocfileOnILockBytes(ILockBytes plkbyt, uint grfMode, uint reserved, out IStorage ppstgOpen);

        [DllImport("ole32.dll")]
        private static extern void ReleaseStgMedium(ref ComTypes.STGMEDIUM pmedium);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern bool GlobalUnlock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        private static extern UIntPtr GlobalSize(IntPtr hMem);
    }
}
