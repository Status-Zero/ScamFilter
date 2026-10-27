using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace ScamFilter.Desktop
{
    /*
     * The developer tabs, which only exist in the developer environment (see App.xaml.cs):
     *
     *   AI viewer   what the model learned (look up any word's weight, the strongest words
     *               each way) and the full arithmetic behind the last verdict
     *   Model       train the model and read the report (MainWindow.xaml.cs)
     *   Developer   the developer environment's data folder, leaving or resetting it, and the
     *               Outlook app registration
     *
     * Everything else in the developer environment is the normal app, unchanged.
     *
     * HOW TO READ THE AI VIEWER
     * The model's score for a message is one sum (see ScamModel):
     *
     *     z = bias + (sum over text features of weight x value) + (sum over flags of weight x flag)
     *     P(scam) = 1 / (1 + e^(-z))
     *
     * "value" is the feature's TF-IDF number for this message (see Featurizer), and "weight" is
     * what training learned for it. So each feature's share of the decision is exactly
     * weight x value, and the shares add up to z. That's what the breakdown lists.
     */
    public partial class MainWindow
    {
        // How many features each list on the AI viewer shows.
        private const int AiListLength = 40;

        // Shows the developer tabs only in the developer environment.
        private void SetUpDeveloperPages()
        {
            DeveloperNav.Visibility = App.DeveloperMode ? Visibility.Visible : Visibility.Collapsed;
            DevDataFolderText.Text = Paths.BaseDir;
        }

        // ------------------------------------------------------------------
        // AI viewer
        // ------------------------------------------------------------------

        private void RefreshAiViewer()
        {
            if (!ScamDetector.ModelExists())
            {
                AiModelSummary.Text = "No model yet. Train one on the Model page.";
                return;
            }
            try
            {
                ScamModel model = ScamDetector.CurrentModel();
                int scamLeaning = 0;
                int safeLeaning = 0;
                foreach (double w in model.TextWeights)
                {
                    if (w > 0.0)
                    {
                        scamLeaning++;
                    }
                    else if (w < 0.0)
                    {
                        safeLeaning++;
                    }
                }
                AiModelSummary.Text = "Logistic regression, trained " + LastTrained().ToString("MMMM d, yyyy 'at' h:mm tt") + ". "
                    + model.Featurizer.Size.ToString("N0") + " text features (" + scamLeaning.ToString("N0") + " lean scam, "
                    + safeLeaning.ToString("N0") + " lean safe) plus " + MetadataFeatures.Count + " hand-set flags. "
                    + "Bias " + Format.Signed(model.Bias, 3) + ". "
                    + "Bands: SAFE below " + Format.Percent(model.TLow, 0) + "%, UNSAFE from " + Format.Percent(model.THigh, 0) + "%. "
                    + "Text counting: " + (model.Featurizer.SublinearTf ? "1 + ln(tf)" : "raw tf")
                    + (model.Featurizer.TypeCopies ? ", with email-only and text-only copies of every n-gram." : ".");
            }
            catch (Exception ex)
            {
                AiModelSummary.Text = "Couldn't read the model: " + ex.Message;
            }
        }

        /*
         * The full arithmetic behind a verdict, for the AI viewer (it replaced the "Technical
         * details" box that used to sit under the result on the Check page).
         */
        private static string ScoringBreakdown(MessageRecord r, Verdict v)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Verdict: " + v.Band + "   (decided by " + v.DecidedBy + ")");
            sb.AppendLine("Type: " + r.Type + "    Channel: " + r.Channel
                + (r.Sender.Length > 0 ? "    Sender: " + r.Sender : "")
                + (r.DisplayName.Length > 0 ? "  (\"" + r.DisplayName + "\")" : ""));
            if (r.Subject.Length > 0)
            {
                sb.AppendLine("Subject: " + r.Subject);
            }
            if (r.Spf.Length > 0 || r.Dkim.Length > 0 || r.Dmarc.Length > 0)
            {
                sb.AppendLine("Sender checks: SPF " + Dash(r.Spf) + ", DKIM " + Dash(r.Dkim) + ", DMARC " + Dash(r.Dmarc));
            }
            if (r.ReplyTo.Length > 0)
            {
                sb.AppendLine("Reply-To: " + r.ReplyTo);
            }

            ScamModel model;
            try
            {
                model = ScamDetector.CurrentModel();
            }
            catch (Exception ex)
            {
                sb.AppendLine();
                sb.AppendLine("(The model couldn't be read: " + ex.Message + ")");
                return sb.ToString().TrimEnd();
            }

            // The same sum the model does, term by term.
            SparseVector x = model.Featurizer.Transform(r);
            double[] flags = MetadataFeatures.Compute(r);
            double textSum = 0.0;
            List<int> order = new List<int>();
            for (int i = 0; i < x.Size; i++)
            {
                textSum += model.TextWeights[x.Indices[i]] * x.Values[i];
                order.Add(i);
            }
            double flagSum = 0.0;
            for (int k = 0; k < flags.Length; k++)
            {
                flagSum += model.MetaWeights[k] * flags[k];
            }
            double z = model.Bias + textSum + flagSum;
            double p = ScamModel.Sigmoid(z);

            sb.AppendLine();
            sb.AppendLine("THE SCORE");
            sb.AppendLine("  bias                                " + Format.Signed(model.Bias, 3));
            sb.AppendLine("  text features (" + x.Size + " in this message)    " + Format.Signed(textSum, 3) + "   (sum of weight x value)");
            sb.AppendLine("  metadata flags                      " + Format.Signed(flagSum, 3));
            sb.AppendLine("  z                                   " + Format.Signed(z, 3));
            sb.AppendLine("  P(scam) = 1 / (1 + e^-z)            " + Format.Fixed(p, 3)
                + "   -> " + model.Band(p) + " (SAFE below " + Format.Fixed(model.TLow, 3) + ", UNSAFE from " + Format.Fixed(model.THigh, 3) + ")");
            if (v.DecidedBy != "model")
            {
                sb.AppendLine("  (Your " + (v.DecidedBy == "blocklist" ? "blocked" : "trusted")
                    + " list made the call. The line above is what the model alone would have said.)");
            }

            sb.AppendLine();
            sb.AppendLine("TEXT FEATURES PUSHING TOWARD SCAM        weight x value = share");
            AppendShares(sb, model, x, order.OrderByDescending(i => model.TextWeights[x.Indices[i]] * x.Values[i]), true);
            sb.AppendLine();
            sb.AppendLine("TEXT FEATURES PUSHING TOWARD SAFE");
            AppendShares(sb, model, x, order.OrderBy(i => model.TextWeights[x.Indices[i]] * x.Values[i]), false);

            sb.AppendLine();
            sb.AppendLine("METADATA FLAGS (hand-set weights; see MetadataFeatures)");
            bool anyFlag = false;
            for (int k = 0; k < flags.Length; k++)
            {
                if (flags[k] != 0.0)
                {
                    anyFlag = true;
                    sb.AppendLine("  " + Format.Signed(model.MetaWeights[k] * flags[k], 3) + "   " + MetadataFeatures.Names[k]
                        + "   (" + MetadataFeatures.Reasons[k] + ")");
                }
            }
            if (!anyFlag)
            {
                sb.AppendLine("  none fired");
            }

            if (v.Links.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("LINKS");
                foreach (LinkInfo link in v.Links)
                {
                    sb.AppendLine("  " + link.ToString().Replace("\n", "\n  "));
                }
            }
            return sb.ToString().TrimEnd();
        }

        // The first few features in `order`, as "share = weight x value   feature".
        private static void AppendShares(StringBuilder sb, ScamModel model, SparseVector x, IEnumerable<int> order, bool towardScam)
        {
            int shown = 0;
            foreach (int i in order)
            {
                int j = x.Indices[i];
                double share = model.TextWeights[j] * x.Values[i];
                if (shown >= 15 || (towardScam ? share <= 0.0 : share >= 0.0))
                {
                    break;
                }
                sb.AppendLine("  " + Format.Signed(share, 3).PadLeft(7) + " = " + Format.Signed(model.TextWeights[j], 3).PadLeft(7)
                    + " x " + Format.Fixed(x.Values[i], 3) + "   " + model.Featurizer.Term(j));
                shown++;
            }
            if (shown == 0)
            {
                sb.AppendLine("  none");
            }
        }

        // Typing in "Look up a word": lists every feature containing what was typed.
        private void AiLookupBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string query = AiLookupBox.Text.Trim().ToLowerInvariant();
            if (query.Length < 2)
            {
                AiLookupResults.Text = "";
                return;
            }
            ShowFeatures(j => FeatureText(j).Contains(query, StringComparison.Ordinal),
                "Features containing \"" + query + "\", strongest first:", true);
        }

        // "Strongest scam words".
        private void AiTopScam_Click(object sender, RoutedEventArgs e)
        {
            ShowFeatures(j => true, "The " + AiListLength + " features that push hardest toward SCAM:", false);
        }

        // "Strongest safe words".
        private void AiTopSafe_Click(object sender, RoutedEventArgs e)
        {
            ShowFeatures(j => true, "The " + AiListLength + " features that push hardest toward SAFE:", false, true);
        }

        // The part of each feature's name a person would search for ("E|w:verify" -> "verify"),
        // worked out once per model in ShowFeatures.
        private ScamModel featureTextModel = null;
        private string[] featureTexts = null;

        // The searchable part of feature j's name.
        private string FeatureText(int j)
        {
            return featureTexts[j];
        }

        /*
         * Lists the model's features that pass `keep`, with their weights.
         * byStrength: strongest in either direction first; otherwise most scam-leaning first
         * (or most safe-leaning, with safeFirst).
         */
        private void ShowFeatures(Func<int, bool> keep, string heading, bool byStrength, bool safeFirst = false)
        {
            ScamModel model;
            try
            {
                model = ScamDetector.CurrentModel();
            }
            catch (Exception ex)
            {
                AiLookupResults.Text = "Couldn't read the model: " + ex.Message;
                return;
            }
            if (featureTextModel != model)
            {
                // Worked out once per model: the searchable text of every feature.
                featureTexts = new string[model.Featurizer.Size];
                for (int j = 0; j < featureTexts.Length; j++)
                {
                    string term = model.Featurizer.Term(j);
                    if (term.Length > 2 && term[1] == '|')
                    {
                        term = term.Substring(2);
                    }
                    featureTexts[j] = term.Length > 2 ? term.Substring(2) : term;
                }
                featureTextModel = model;
            }
            double[] w = model.TextWeights;
            IEnumerable<int> matching = Enumerable.Range(0, w.Length).Where(keep);
            IEnumerable<int> sorted = byStrength ? matching.OrderByDescending(j => Math.Abs(w[j]))
                : safeFirst ? matching.OrderBy(j => w[j]) : matching.OrderByDescending(j => w[j]);
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(heading);
            sb.AppendLine("   weight     idf   feature");
            int shown = 0;
            foreach (int j in sorted)
            {
                if (shown >= AiListLength)
                {
                    break;
                }
                sb.AppendLine("  " + Format.Signed(w[j], 3).PadLeft(7) + "  " + Format.Fixed(model.Featurizer.Idf(j), 2).PadLeft(6)
                    + "   " + model.Featurizer.Term(j));
                shown++;
            }
            if (shown == 0)
            {
                sb.AppendLine("  no feature contains that. The model never saw it often enough to learn it, so it counts 0.");
            }
            sb.AppendLine();
            sb.AppendLine("w: = word, b: = two-word phrase, c: = 3-5 letter piece (a space marks a word edge).");
            sb.AppendLine("E| and T| = the emails-only and texts-only copies.");
            AiLookupResults.Text = sb.ToString().TrimEnd();
        }

        // ------------------------------------------------------------------
        // Developer page
        // ------------------------------------------------------------------

        private void LeaveDeveloper_Click(object sender, RoutedEventArgs e)
        {
            App.Restart(false);
        }

        // "Reset developer environment": deletes the developer data folder (after checking it really
        // is that folder) and starts the developer environment again from the built-in data.
        private void ResetDeveloper_Click(object sender, RoutedEventArgs e)
        {
            MessageBoxResult answer = MessageBox.Show(this,
                "Delete the developer environment's data folder and start it again from the built-in data?\n\n" + Paths.BaseDir
                + "\n\nReal accounts aren't affected.",
                "Reset developer environment", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes)
            {
                return;
            }
            // Safety check: only ever delete the developer folder, never the real one.
            string folder = Path.GetFullPath(Paths.BaseDir).TrimEnd(Path.DirectorySeparatorChar);
            string expected = Path.GetFullPath(App.DeveloperDataFolder).TrimEnd(Path.DirectorySeparatorChar);
            if (!App.DeveloperMode || !string.Equals(folder, expected, StringComparison.OrdinalIgnoreCase))
            {
                DevStatus.Text = "Not resetting: this isn't the developer environment's folder.";
                return;
            }
            try
            {
                if (outlookTimer != null)
                {
                    outlookTimer.Stop();
                }
                if (trainingTimer != null)
                {
                    trainingTimer.Stop();
                }
                ScamDetector.Unload();
                Directory.Delete(folder, true);
            }
            catch (Exception ex)
            {
                DevStatus.Text = "Couldn't delete everything (" + ex.Message + "). Close other programs using the folder and try again.";
                return;
            }
            App.Restart(true);
        }
    }
}
