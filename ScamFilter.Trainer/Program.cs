using System;
using ScamFilter;

namespace ScamFilter.TrainerApp
{
    /*
     * Command-line front door to the backend. From the solution folder:
     *
     *   dotnet run --project ScamFilter.Trainer                 train the model and print the report
     *   dotnet run --project ScamFilter.Trainer -- demo         run the detector on a few demo messages
     *   dotnet run --project ScamFilter.Trainer -- import-...   add a public dataset to data/records.jsonl
     *                                                           (see DatasetTools, or run with "help")
     *
     * It reads data/ and writes model/ in the folder you run it from (missing default data
     * files are written out first). The desktop app can train too, with its "Train model" button.
     */
    public static class Program
    {
        // Picks the command from the first argument ("train" if there is none) and runs it.
        public static int Main(string[] args)
        {
            string command = args.Length > 0 ? args[0] : "train";
            if (command.StartsWith("import-", StringComparison.Ordinal) || command == "fix-conflicts" || command == "fix-labels")
            {
                return DatasetTools.Run(command, args);
            }
            if (command == "help" || command == "--help")
            {
                Console.WriteLine("Commands: train (default), demo, import-mbox, import-dir, import-csv, import-variety, fix-conflicts, fix-labels");
                DatasetTools.PrintUsage();
                return 0;
            }
            Paths.EnsureDefaultData();
            if (command == "demo")
            {
                Demo();
            }
            else
            {
                Trainer.Train(new TrainingSettings(), Console.WriteLine);
            }
            return 0;
        }

        // "demo": checks six example messages and prints each verdict with its reasons.
        private static void Demo()
        {
            Console.WriteLine("=== Demo ===");
            ScamDetector.CheckText("+1 (602) 555-0181",
                "E-ZPass: unpaid toll of $3.75 on your account. Pay within 24 hrs to avoid a $45 fee: ezpass-paycenter.top/pay");
            ScamDetector.CheckText("+1 (702) 555-0150",
                "FedEx: we were unable to deliver your parcel. Confirm your address and pay the $1.50 fee at fedex-redeliver.top/confirm");
            ScamDetector.CheckText("72166",
                "Your Venmo code is 448210. Don't share it with anyone. We'll never ask for this code.");
            ScamDetector.CheckText("+1 (213) 555-0110",
                "hey is this jordan? we met at the career fair last week, you said to text you");
            ScamDetector.CheckEmail("no-reply@accounts.google.com", "Google", "Security alert",
                "A new sign-in on Windows. If this was you, you don't need to do anything. If not, we'll help you secure your account.");
            ScamDetector.CheckEmail("help.desk.apple@outlook.com", "Apple Support", "Your Apple ID has been locked",
                "We detected suspicious activity. Verify your identity within 24 hours at appleid-verify-center.com or your account will be deleted.");
        }
    }
}
