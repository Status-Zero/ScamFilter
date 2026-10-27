using System;
using System.Windows;

namespace ScamFilter.Desktop
{
    /*
     * Asks for a new account name or a new password. validate returns why the input is refused,
     * or null to accept it; Value is the accepted text when ShowDialog() returns true.
     */
    public partial class InputDialog : Window
    {
        private readonly bool password;
        private readonly Func<string, string> validate;

        public string Value = "";   // the accepted text, after ShowDialog() returns true

        private InputDialog(Window owner, string title, string explanation, bool password, Func<string, string> validate)
        {
            InitializeComponent();
            Owner = owner;
            Title = title;
            Heading.Text = title;
            Explanation.Text = explanation;
            Explanation.Visibility = explanation.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
            this.password = password;
            this.validate = validate;
            TextPanel.Visibility = password ? Visibility.Collapsed : Visibility.Visible;
            PasswordPanel.Visibility = password ? Visibility.Visible : Visibility.Collapsed;
            Loaded += (s, e) =>
            {
                if (password)
                {
                    PasswordInput.Focus();
                }
                else
                {
                    ValueInput.Focus();
                    ValueInput.SelectAll();
                }
            };
        }

        // A dialog asking for text (like a new account name), filled in with `current`.
        public static InputDialog ForText(Window owner, string title, string label, string current, Func<string, string> validate)
        {
            InputDialog d = new InputDialog(owner, title, "", false, validate);
            d.TextLabel.Text = label;
            d.ValueInput.Text = current;
            return d;
        }

        // A dialog asking for a new password, typed twice.
        public static InputDialog ForNewPassword(Window owner, string title, string explanation, Func<string, string> validate)
        {
            return new InputDialog(owner, title, explanation, true, validate);
        }

        // "OK": accepts the input if validate has no objection (and both passwords match).
        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            string value = password ? PasswordInput.Password : ValueInput.Text.Trim();
            string problem = validate(value);
            if (problem == null && password && PasswordInput.Password != PasswordAgain.Password)
            {
                problem = "The two passwords don't match.";
            }
            if (problem != null)
            {
                Status.Text = problem;
                return;
            }
            Value = value;
            DialogResult = true;
        }
    }
}
