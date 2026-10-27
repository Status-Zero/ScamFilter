using System.Globalization;

namespace ScamFilter
{
    /*
     * Number formatting that looks the same on every computer.
     *
     * C# formats numbers using the computer's region settings by default, so 0.5 could print
     * as "0,5" in Germany. InvariantCulture always uses a "." for decimals, which also keeps
     * the saved model file readable everywhere.
     */
    public static class Format
    {
        /// <summary>Fixed(3.14159, 2) gives "3.14"</summary>
        public static string Fixed(double x, int decimals)
        {
            return x.ToString("F" + decimals, CultureInfo.InvariantCulture);
        }

        /// <summary>Signed(2.5, 2) gives "+2.50", Signed(-2, 2) gives "-2.00"</summary>
        public static string Signed(double x, int decimals)
        {
            if (double.IsNegative(x))
            {
                return Fixed(x, decimals);
            }
            return "+" + Fixed(x, decimals);
        }

        /// <summary>Percent(0.948, 1) gives "94.8"</summary>
        public static string Percent(double fraction, int decimals)
        {
            return Fixed(100.0 * fraction, decimals);
        }

        /// <summary>Exact, round-trippable text for saving numbers to a file.</summary>
        public static string Exact(double x)
        {
            return x.ToString("R", CultureInfo.InvariantCulture);
        }

        // Reads a number written by Exact (always with "." as the decimal point, whatever the PC's language).
        public static double Parse(string s)
        {
            return double.Parse(s, CultureInfo.InvariantCulture);
        }
    }
}
