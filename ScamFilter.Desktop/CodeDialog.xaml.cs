using System.Windows;

namespace ScamFilter.Desktop
{
    // Shows a recovery code. "Done" only works once the box saying it was saved is checked.
    public partial class CodeDialog : Window
    {
        public CodeDialog(Window owner, string code)
        {
            InitializeComponent();
            Owner = owner;
            if (owner == null || !owner.IsVisible)
            {
                WindowStartupLocation = WindowStartupLocation.CenterScreen;
            }
            CodeText.Text = code;
            Closing += (s, e) =>
            {
                // Closing with the X before saving it: ask once, since the code can't be shown again.
                if (SavedBox.IsChecked != true)
                {
                    MessageBoxResult answer = MessageBox.Show(this,
                        "This code won't be shown again. Close without saving it?\n\n(You can make a new one later on the Account page.)",
                        "Your recovery code", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                    e.Cancel = answer != MessageBoxResult.Yes;
                }
            };
        }

        // "Copy": puts the code on the clipboard.
        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(CodeText.Text);
            }
            catch (System.Runtime.InteropServices.ExternalException)
            {
                // another program is holding the clipboard; writing it down still works
            }
        }

        // "I saved it somewhere safe": only then can the dialog be closed with Done.
        private void SavedBox_Click(object sender, RoutedEventArgs e)
        {
            DoneButton.IsEnabled = SavedBox.IsChecked == true;
        }

        // "Done".
        private void Done_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
        }
    }
}
