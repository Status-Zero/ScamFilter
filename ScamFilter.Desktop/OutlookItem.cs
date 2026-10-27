using System.ComponentModel;
using System.Windows;
using System.Windows.Media;

namespace ScamFilter.Desktop
{
    /*
     * One row on the Outlook page. The list shows these properties (see MainWindow.xaml).
     *
     * INotifyPropertyChanged lets a row update itself on screen: when an email is opened for a
     * full check (pictures read, every detail), its badge can change, and raising PropertyChanged
     * tells the list to redraw just that row.
     */
    public class OutlookItem : INotifyPropertyChanged
    {
        // Raised when BandText or BandBrush changes, so the list redraws the row.
        public event PropertyChangedEventHandler PropertyChanged;

        private string bandText = "";
        private Brush bandBrush = Brushes.Gray;

        // "Safe", "Caution" or "Unsafe" on the badge.
        public string BandText
        {
            get { return bandText; }
            set { bandText = value; Changed("BandText"); }
        }

        // The badge's color.
        public Brush BandBrush
        {
            get { return bandBrush; }
            set { bandBrush = value; Changed("BandBrush"); }
        }

        public string From { get; set; }         // the sender's name (or address)
        public string Subject { get; set; }      // the subject line
        public string When { get; set; }         // when it arrived ("3:42 PM" today, "Oct 24" before)
        public string Tip { get; set; }          // the tooltip: the full sender and the start of the message
        public FontWeight Weight { get; set; }   // bold while unread, like Outlook

        public GraphMailClient.MailItem Mail { get; set; }   // the email, as listed by Graph
        public Verdict Verdict { get; set; }                 // its verdict

        // Tells the list that a property changed.
        private void Changed(string property)
        {
            PropertyChangedEventHandler handler = PropertyChanged;
            if (handler != null)
            {
                handler(this, new PropertyChangedEventArgs(property));
            }
        }
    }
}
