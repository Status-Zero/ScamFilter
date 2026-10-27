using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ScamFilter.Desktop
{
    /*
     * "Asynchronous" drag and drop: what the new Outlook needs before it hands over an email.
     *
     * ============================================================================
     *  THE PROBLEM
     * ============================================================================
     * The new Outlook for Windows (and Outlook on the web, and other programs built on the
     * Chromium browser engine) doesn't have the dragged email as a file yet when the drag
     * starts. It offers a file ("FileDrop"), but only writes the file once the program it's
     * dropped on says "I can wait for it". A program that just asks for the file, the way WPF
     * does, gets nothing: the email is dropped and nothing happens. File Explorer knows how to
     * say it, which is why dragging an email to the desktop works.
     *
     * ============================================================================
     *  THE FIX
     * ============================================================================
     * Windows has a small COM interface for exactly this, IDataObjectAsyncCapability, on the
     * dragged data itself (see the "Dragging and dropping shell objects asynchronously" page in
     * Microsoft's documentation). The drop target:
     *   1. asks GetAsyncMode: does this source work that way?
     *   2. if so, calls StartOperation ("I can wait"), then reads the data as usual
     *      (Outlook writes the file now),
     *   3. calls EndOperation when it's done, so the source can clean up.
     * Start() does steps 1 and 2, End() does step 3. ScamFilter reads the data right away on the
     * window's thread (the file is small), the same "sync over async" approach Windows Forms
     * uses in .NET 10.
     *
     * One catch: WPF wraps the dragged COM object in its own DataObject and doesn't pass this
     * interface through. The original object is still inside it (in a private field), so Start()
     * finds it by looking through the wrapper's fields with reflection. If a future .NET hides
     * it differently, Start() returns null and dropping simply works as before.
     */
    public sealed class AsyncDrop
    {
        // DROPEFFECT_COPY: the drop made a copy (nothing for the source to delete).
        private const uint DropEffectCopy = 1;

        // E_FAIL: tells the source the drop didn't work out.
        private const int Failed = unchecked((int) 0x80004005);

        /*
         * The COM interface (also called IAsyncOperation). As with every COM interface, the
         * methods must be listed in their fixed order. Each returns an HRESULT, which .NET turns
         * into an exception if it's an error.
         */
        [ComImport, Guid("3D8B0590-F691-11d2-8EA9-006097DF5BD4"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IDataObjectAsyncCapability
        {
            void SetAsyncMode([MarshalAs(UnmanagedType.Bool)] bool doAsync);
            void GetAsyncMode([MarshalAs(UnmanagedType.Bool)] out bool isAsync);
            void StartOperation(IntPtr reserved);
            void InOperation([MarshalAs(UnmanagedType.Bool)] out bool inOperation);
            void EndOperation(int result, IntPtr reserved, uint effects);
        }

        private readonly IDataObjectAsyncCapability source;
        private bool ended = false;

        private AsyncDrop(IDataObjectAsyncCapability source)
        {
            this.source = source;
        }

        /*
         * Call during the drop, before reading anything. Returns null when the dragged data
         * doesn't need this (File Explorer, classic Outlook): just read it as usual. Otherwise
         * the source is now ready to hand its files over; call End() once they've been read.
         */
        public static AsyncDrop Start(System.Windows.IDataObject data)
        {
            try
            {
                IDataObjectAsyncCapability capability = FindCapability(data, 0, new HashSet<object>(ReferenceEqualityComparer.Instance));
                if (capability == null)
                {
                    return null;
                }
                bool isAsync;
                capability.GetAsyncMode(out isAsync);
                if (!isAsync)
                {
                    return null;
                }
                capability.StartOperation(IntPtr.Zero);
                return new AsyncDrop(capability);
            }
            catch (Exception)
            {
                return null;   // the source turned it down: read the data the ordinary way
            }
        }

        // Tells the source the drop is finished (worked: a copy was made; or it didn't work out).
        public void End(bool worked)
        {
            if (ended)
            {
                return;
            }
            ended = true;
            try
            {
                source.EndOperation(worked ? 0 : Failed, IntPtr.Zero, worked ? DropEffectCopy : 0);
            }
            catch (Exception)
            {
                // the source is gone or doesn't care; nothing to do
            }
        }

        /*
         * Looks through an object's fields (and their fields, a few levels deep) for the dragged
         * COM object, recognized by having the interface. `seen` stops it going round in circles.
         * Numbers, text, pointers and the like can't hold it, so they're skipped.
         */
        private static IDataObjectAsyncCapability FindCapability(object holder, int depth, HashSet<object> seen)
        {
            if (holder == null || depth > 3 || !seen.Add(holder))
            {
                return null;
            }
            IDataObjectAsyncCapability capability = holder as IDataObjectAsyncCapability;   // for a COM object, this asks it
            if (capability != null)
            {
                return capability;
            }
            Type type = holder.GetType();
            if (type.IsPrimitive || type.IsEnum || type.IsPointer || holder is string || holder is Delegate || holder is Array)
            {
                return null;
            }
            for (Type t = type; t != null && t != typeof(object); t = t.BaseType)
            {
                foreach (FieldInfo field in t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                {
                    if (field.FieldType.IsPrimitive || field.FieldType.IsPointer || field.FieldType.IsEnum || field.FieldType == typeof(string))
                    {
                        continue;
                    }
                    object value;
                    try
                    {
                        value = field.GetValue(holder);
                    }
                    catch (Exception)
                    {
                        continue;
                    }
                    IDataObjectAsyncCapability found = FindCapability(value, depth + 1, seen);
                    if (found != null)
                    {
                        return found;
                    }
                }
            }
            return null;
        }
    }
}
