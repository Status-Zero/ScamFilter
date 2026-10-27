using System.Windows.Media;

namespace ScamFilter.Desktop
{
    // One row on the History page. The page's list shows these properties (see MainWindow.xaml).
    public class HistoryItem
    {
        public string Time { get; set; }       // when it was checked ("3:42 PM")
        public string BandText { get; set; }   // "Safe", "Caution" or "Unsafe"
        public Brush BandBrush { get; set; }   // the band's color
        public string Preview { get; set; }    // the first line or so of the message

        // Kept so the result can be shown again without re-checking.
        public MessageRecord Record { get; set; }   // the message as it was checked
        public Verdict Verdict { get; set; }        // the result
    }
}
