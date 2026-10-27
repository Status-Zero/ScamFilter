using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace ScamFilter
{
    /*
     * Trains the scam model from start to finish.   >>> START READING THE PROJECT HERE <<<
     *
     * Run it with the console trainer (dotnet run --project ScamFilter.Trainer) or with the
     * "Train model" button in the app. Both call Trainer.Train().
     *
     * ============================================================================
     *  WHAT "TRAINING A MODEL" MEANS
     * ============================================================================
     *
     * A normal program follows rules a person wrote, like
     *
     *     if (text.Contains("gift card")) { FlagAsScam(); }
     *
     * That breaks down fast. Scammers change their wording constantly, and plenty of legit
     * messages say "gift card" too. There are far too many patterns to write by hand.
     *
     * Machine learning flips it around. Instead of writing the rules ourselves, we:
     *
     *   1. Collect lots of example messages, each labeled by a person: 1 = scam, 0 = not scam.
     *   2. Turn every message into a list of numbers that describe it (its FEATURES).
     *      See Featurizer and MetadataFeatures.
     *   3. Let the program adjust another big list of numbers (its WEIGHTS) until its guesses
     *      match the labels as closely as possible. That adjusting is "training".
     *      See LogisticTrainer.
     *
     * The finished weights ARE the model. They get saved to a file. Later, ScamDetector loads
     * that file and uses the weights to guess on new messages nobody has labeled.
     *
     * The kind of model used here is called LOGISTIC REGRESSION. ScamModel explains how it
     * turns features + weights into a guess.
     *
     * ============================================================================
     *  WHY THE DATA IS SPLIT THREE WAYS
     * ============================================================================
     *
     * Think of a student getting ready for an exam:
     *
     *   TRAIN set       = the practice problems. The model learns from these, and only these.
     *   VALIDATION set  = a practice quiz. The model never learns from it. We use it to make
     *                     decisions: when to stop training, and where to put the thresholds.
     *   TEST set        = the final exam. Used ONCE, at the very end, to see how the model does
     *                     on messages it has never seen in any way.
     *
     * Why not just grade it on the practice problems? Because a model can score 100% on
     * those simply by memorizing them, and then fail on anything new. Memorizing instead of
     * learning general patterns is called OVERFITTING, and it's the main thing to guard
     * against. Only scores on unseen data tell you how the model will do in real life.
     *
     * Two kinds of final exam, because they answer different questions:
     *
     *   TEST SET (random)   a random 15% of the data. Answers: "on messages like the ones it
     *                       learned from, how often is it right?" This is the headline score.
     *   GENERALIZATION      whole SOURCES held out (HoldoutSources). Messages from the same
     *   CHECK               dataset share quirks (same years, same formatting, same scam
     *                       campaigns), so a random test set flatters the model a little. A
     *                       source it has never seen at all answers: "how does it do on a
     *                       different kind of message?" That's closer to real life, where new
     *                       scams keep appearing. Expect this score to be lower.
     *
     * Duplicates are removed when data is imported (see DatasetTools), so the same message can't
     * be in both the training data and the test.
     *
     * ============================================================================
     *  THE PIPELINE (what Train() does, in order)
     * ============================================================================
     *   1. Load data/records.jsonl, plus data/feedback.jsonl (corrections saved by the app).
     *      Unlabeled records are skipped (you can't learn from them).
     *   2. Split into train / validation / test, plus any held-out sources. Corrections always
     *      go to training (see CorrectionCopies), never to the exams.
     *   3. Add OCR-style copies of raw training records (training set only). See OcrNoiser.
     *   4. Build the vocabulary of text features from the real training records.
     *   5. Train: adjust the weights, stopping when the validation score stops improving.
     *   6. Pick the SAFE / CAUTION / UNSAFE thresholds using the validation set.
     *   7. Grade the model on the test set, print what it learned, and save it.
     */
    public static class Trainer
    {
        // Held while training, so two ScamFilter windows never train (and save the model) at once.
        public static string TrainingLockPath
        {
            get { return Path.Combine(Path.GetDirectoryName(Paths.ModelFile), "training.lock"); }
        }

        /*
         * Trains and saves the model. If another ScamFilter window is training right now, this
         * waits for it first (both use the same model file; see FileLock in SharedFiles.cs).
         */
        public static TrainingSummary Train(TrainingSettings settings, Action<string> output)
        {
            FileLock held = FileLock.TryAcquire(TrainingLockPath);
            if (held == null)
            {
                output("Another ScamFilter window is training the model right now. Waiting for it to finish...");
                held = FileLock.Acquire(TrainingLockPath, TimeSpan.FromMinutes(30));
                if (held == null)
                {
                    throw new IOException("Another ScamFilter window has been training for 30 minutes. Try again later.");
                }
            }
            try
            {
                return TrainNow(settings, output);
            }
            finally
            {
                held.Release();
            }
        }

        // True while another ScamFilter window is training (the app skips its background run then).
        public static bool IsTrainingElsewhere()
        {
            FileLock probe = FileLock.TryAcquire(TrainingLockPath);
            if (probe == null)
            {
                return true;
            }
            probe.Release();
            return false;
        }

        // The training itself (steps 1 to 7 in the class comment). Train calls this while
        // holding the training lock.
        private static TrainingSummary TrainNow(TrainingSettings settings, Action<string> output)
        {
            Stopwatch clock = Stopwatch.StartNew();
            // Every report line goes to the caller (console or app) AND into a copy that's saved
            // as model/training_report.txt, so the app can show the last report later.
            StringBuilder report = new StringBuilder();
            report.AppendLine("Trained " + DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
            Action<string> log = line =>
            {
                report.AppendLine(line);
                output(line);
            };
            log("=== Training the scam model ===");

            // ---- 1. Load ----
            List<MessageRecord> all = MessageRecord.LoadJsonl(Paths.RecordsFile);
            List<MessageRecord> feedback = File.Exists(Paths.FeedbackFile)
                ? MessageRecord.LoadJsonl(Paths.FeedbackFile) : new List<MessageRecord>();
            List<MessageRecord> labeled = new List<MessageRecord>();
            foreach (MessageRecord r in all)
            {
                if (r.Label == 0 || r.Label == 1)
                {
                    labeled.Add(r);
                }
            }
            // If the same message was marked more than once (changed your mind?), the last mark wins.
            List<MessageRecord> corrections = new List<MessageRecord>();
            Dictionary<string, int> positionOf = new Dictionary<string, int>();
            foreach (MessageRecord r in feedback)
            {
                if (r.Label != 0 && r.Label != 1)
                {
                    continue;
                }
                string key = r.FullText().Trim();
                int position;
                if (positionOf.TryGetValue(key, out position))
                {
                    corrections[position] = r;
                }
                else
                {
                    positionOf[key] = corrections.Count;
                    corrections.Add(r);
                }
            }
            int unlabeled = all.Count - labeled.Count;
            log("Loaded " + all.Count + " records from data/records.jsonl"
                + (feedback.Count > 0 ? " + " + feedback.Count + " from data/feedback.jsonl" : "")
                + " (" + unlabeled + " unlabeled, skipped)");

            // ---- 2. Split ----
            // a) Whole sources can be held out as a "generalization check": the model never sees
            //    anything from them, so they show how it does on a different KIND of message.
            //    Others are "training only" (TrainOnlySources): small hand-made sets that are there
            //    to teach, not to grade with.
            HashSet<string> holdoutSources = new HashSet<string>(settings.HoldoutSources);
            HashSet<string> trainOnlySources = new HashSet<string>(settings.TrainOnlySources);
            List<MessageRecord> holdout = new List<MessageRecord>();
            List<MessageRecord> trainOnly = new List<MessageRecord>();
            List<MessageRecord> rest = new List<MessageRecord>();
            foreach (MessageRecord r in labeled)
            {
                if (holdoutSources.Contains(r.Source))
                {
                    holdout.Add(r);
                }
                else if (trainOnlySources.Contains(r.Source))
                {
                    trainOnly.Add(r);
                }
                else
                {
                    rest.Add(r);
                }
            }
            // b) Near-duplicates (the same campaign or template with small changes) are grouped,
            //    and a group always goes to ONE side of every split. Otherwise a copy of a test
            //    message could be in the training data, and the test would flatter the model.
            //    See NearDuplicates.
            Dictionary<MessageRecord, int> groupOf = new Dictionary<MessageRecord, int>();
            int[] groupIds = NearDuplicates.Groups(rest);
            HashSet<int> distinctGroups = new HashSet<int>();
            for (int i = 0; i < rest.Count; i++)
            {
                groupOf[rest[i]] = groupIds[i];
                distinctGroups.Add(groupIds[i]);
            }
            log("Near-duplicate groups: " + rest.Count + " records in " + distinctGroups.Count
                + " groups (each group stays on one side of the split)");

            // c) The test set ("final exam"): a random TestFraction of everything else.
            // d) The validation set ("practice quiz"): ValidationFraction of what's left.
            //    Everything remaining is training data.
            JavaRandom random = new JavaRandom(settings.Seed);
            List<MessageRecord> test = new List<MessageRecord>();
            List<MessageRecord> remaining = new List<MessageRecord>();
            StratifiedSplit(rest, groupOf, settings.TestFraction, random, test, remaining);
            List<MessageRecord> validation = new List<MessageRecord>();
            List<MessageRecord> train = new List<MessageRecord>();
            StratifiedSplit(remaining, groupOf, settings.ValidationFraction, random, validation, train);

            // e) The user's own corrections: always training data, never exam questions. They're
            //    the most valuable examples there are (real messages, marked by the person who got
            //    them), and they're kept out of the split so adding one doesn't reshuffle which
            //    records land in the test set. Each is added CorrectionCopies times: a single
            //    example among thousands barely moves the weights, and repeating it is the simple
            //    way to say "this one counts extra".
            //    The training-only example sets are added TrainOnlyCopies times, for the same
            //    reason: a few hundred modern examples next to 15,000 older public ones would
            //    otherwise barely register.
            for (int copy = 0; copy < settings.TrainOnlyCopies; copy++)
            {
                train.AddRange(trainOnly);
            }
            if (trainOnly.Count > 0)
            {
                log("Training-only examples (" + string.Join(", ", settings.TrainOnlySources) + "): " + trainOnly.Count
                    + ", each counted " + settings.TrainOnlyCopies + " times");
            }
            for (int copy = 0; copy < settings.CorrectionCopies; copy++)
            {
                train.AddRange(corrections);
            }
            if (corrections.Count > 0)
            {
                log("Your corrections: " + corrections.Count + ", each counted " + settings.CorrectionCopies + " times in training");
            }
            PrintSplit("train", train, log);
            PrintSplit("validation", validation, log);
            PrintSplit("test", test, log);
            if (holdout.Count > 0)
            {
                PrintSplit("held out", holdout, log);
            }

            // ---- 3. OCR-style copies (training only; validation and test must stay real) ----
            // Every text message gets a copy, since texts are what people screenshot most.
            // Every 5th email does too: enough to learn OCR noise, without doubling the memory
            // that long emails take.
            // (Corrections are in `train` several times; the vocabulary should count each one once.)
            List<MessageRecord> realTrain = new List<MessageRecord>();
            HashSet<MessageRecord> seen = new HashSet<MessageRecord>();
            foreach (MessageRecord r in train)
            {
                if (seen.Add(r))
                {
                    realTrain.Add(r);
                }
            }
            if (settings.AugmentOcr)
            {
                OcrNoiser noiser = new OcrNoiser(settings.Seed, settings.OcrNoiseRate);
                int added = 0;
                int emails = 0;
                foreach (MessageRecord r in realTrain)
                {
                    if (r.IsOcr())
                    {
                        continue;
                    }
                    if (r.IsEmail())
                    {
                        emails++;
                        if (emails % 5 != 0)
                        {
                            continue;
                        }
                    }
                    train.Add(noiser.NoisyCopy(r));
                    added++;
                }
                log("Added " + added + " simulated-OCR copies to the training set");
            }

            // ---- 4. Vocabulary ----
            // Built from the REAL training records only. The OCR copies are near-duplicates of
            // them, so including them would make every n-gram look twice as common as it is.
            Featurizer featurizer = Featurizer.Build(realTrain, settings.MinDf, settings.MaxFeatures,
                settings.SublinearTf, settings.TypeCopies);
            log("Vocabulary: " + featurizer.Size + " n-grams (min df " + settings.MinDf
                + (settings.SublinearTf ? ", sublinear tf" : "") + (settings.TypeCopies ? ", email/text copies" : "") + ")");

            // A fresh model: all text weights start at 0 (no opinion yet), metadata weights start
            // at their hand-set values.
            ScamModel model = new ScamModel(featurizer, MetadataFeatures.DefaultWeights());

            // Turn every record into numbers once, up front, instead of on every epoch.
            List<LogisticTrainer.Example> trainExamples = LogisticTrainer.ToExamples(featurizer, train);
            List<LogisticTrainer.Example> validationExamples = LogisticTrainer.ToExamples(featurizer, validation);
            List<LogisticTrainer.Example> testExamples = LogisticTrainer.ToExamples(featurizer, test);
            List<LogisticTrainer.Example> holdoutExamples = LogisticTrainer.ToExamples(featurizer, holdout);

            // ---- 5. Train ----
            log("");
            LogisticTrainer trainer = new LogisticTrainer();
            trainer.LearningRate = settings.LearningRate;
            trainer.L2 = settings.L2Lambda;
            trainer.MaxEpochs = settings.MaxEpochs;
            trainer.Patience = settings.Patience;
            trainer.Seed = settings.Seed;
            trainer.TrainMetaWeights = settings.TrainMetaWeights;
            trainer.Train(model, trainExamples, validationExamples, log);

            // ---- 6. Thresholds ----
            // Score every validation message with the trained model, then let ThresholdPicker
            // find the cut-off points that hit the precision and recall targets.
            log("");
            log("Thresholds (picked on validation):");
            double[] scores = new double[validationExamples.Count];
            int[] labels = new int[validationExamples.Count];
            for (int i = 0; i < scores.Length; i++)
            {
                LogisticTrainer.Example ex = validationExamples[i];
                scores[i] = ScamModel.Sigmoid(model.Logit(ex.X, ex.Flags));
                labels[i] = ex.Y;
            }
            ThresholdPicker.Result thresholds = ThresholdPicker.Pick(scores, labels,
                settings.PrecisionTarget, settings.RecallTarget, settings.RealWorldScamRate);
            model.TLow = thresholds.TLow;
            model.THigh = thresholds.THigh;
            thresholds.Print(settings.PrecisionTarget, settings.RecallTarget, settings.RealWorldScamRate, log);

            // ---- 7. Final exam, generalization check, what it learned, save ----
            Evaluator.Result result = Evaluator.Report("Test set report (a random " + Format.Percent(settings.TestFraction, 0)
                + "% the model never trained on)", model, test, testExamples, settings.RealWorldScamRate, log);
            if (holdout.Count > 0)
            {
                Evaluator.Report("Generalization check (whole sources never used in training: "
                    + string.Join(", ", settings.HoldoutSources) + ")", model, holdout, holdoutExamples, settings.RealWorldScamRate, log);
            }
            model.PrintTopWeights(15, log);

            model.Save(Paths.ModelFile);
            ScamDetector.Unload();   // so the detector reloads the new model the next time it's used
            log("");
            log("Saved model/scam_model.txt  (" + Format.Fixed(clock.Elapsed.TotalSeconds, 1) + " s)");
            SharedFiles.WriteAtomically(Paths.ReportFile, report.ToString());

            TrainingSummary summary = new TrainingSummary();
            summary.TrainCount = realTrain.Count;
            summary.ValidationCount = validation.Count;
            summary.TestCount = test.Count;
            summary.VocabularySize = featurizer.Size;
            summary.TLow = model.TLow;
            summary.THigh = model.THigh;
            summary.TestAuc = result.Auc;
            summary.TestAccuracy = result.Accuracy;
            return summary;
        }

        /*
         * Moves about `fraction` of the records into `taken` and the rest into `left`, moving
         * whole near-duplicate GROUPS at a time (groupOf gives each record's group).
         *
         * "Stratified" means scams and non-scams are split SEPARATELY, so both sides keep the
         * same scam ratio. With a plain random split, a small validation set could end up with
         * almost no scams just by bad luck. A group counts as "scam" if most of it is.
         *
         * Groups are shuffled, then taken one by one until the taken records reach the target
         * count. (Groups vary in size, so the fraction comes out close to, not exactly, the target.)
         */
        private static void StratifiedSplit(List<MessageRecord> input, Dictionary<MessageRecord, int> groupOf,
                                            double fraction, JavaRandom random,
                                            List<MessageRecord> taken, List<MessageRecord> left)
        {
            // group number -> its records, in first-seen order (so every run is identical)
            Dictionary<int, List<MessageRecord>> members = new Dictionary<int, List<MessageRecord>>();
            List<int> order = new List<int>();
            foreach (MessageRecord r in input)
            {
                int g = groupOf[r];
                List<MessageRecord> list;
                if (!members.TryGetValue(g, out list))
                {
                    list = new List<MessageRecord>();
                    members[g] = list;
                    order.Add(g);
                }
                list.Add(r);
            }
            List<List<MessageRecord>> scamGroups = new List<List<MessageRecord>>();
            List<List<MessageRecord>> legitGroups = new List<List<MessageRecord>>();
            int scamRecords = 0;
            int legitRecords = 0;
            foreach (int g in order)
            {
                List<MessageRecord> list = members[g];
                int scams = 0;
                foreach (MessageRecord r in list)
                {
                    scams += r.Label == 1 ? 1 : 0;
                }
                if (scams * 2 > list.Count)
                {
                    scamGroups.Add(list);
                    scamRecords += list.Count;
                }
                else
                {
                    legitGroups.Add(list);
                    legitRecords += list.Count;
                }
            }
            random.Shuffle(scamGroups);
            random.Shuffle(legitGroups);
            TakeGroups(scamGroups, (int) Math.Floor(scamRecords * fraction + 0.5), taken, left);
            TakeGroups(legitGroups, (int) Math.Floor(legitRecords * fraction + 0.5), taken, left);
        }

        // Takes groups until `target` records are taken (stopping before a group that would
        // overshoot by more than it undershoots); everything else goes to `left`.
        private static void TakeGroups(List<List<MessageRecord>> groups, int target,
                                       List<MessageRecord> taken, List<MessageRecord> left)
        {
            int count = 0;
            foreach (List<MessageRecord> group in groups)
            {
                bool take = count < target && (count + group.Count - target) <= (target - count);
                if (take)
                {
                    taken.AddRange(group);
                    count += group.Count;
                }
                else
                {
                    left.AddRange(group);
                }
            }
        }

        // Prints one line of counts for a split, so you can sanity-check the balance.
        private static void PrintSplit(string name, List<MessageRecord> records, Action<string> log)
        {
            int scams = 0;
            int ocr = 0;
            foreach (MessageRecord r in records)
            {
                scams += r.Label;
                if (r.IsOcr())
                {
                    ocr++;
                }
            }
            log("  " + name.PadRight(10) + " " + records.Count.ToString().PadLeft(5) + " records  (" + scams
                + " scam, " + (records.Count - scams) + " not scam; " + ocr + " OCR)");
        }
    }

    // Every training setting in one place. The defaults are good starting points.
    public class TrainingSettings
    {
        // Sources held out ENTIRELY as a generalization check: the model never trains on them, so
        // they show how it handles a different kind of message than it learned from. The default
        // holds out the smoke-test examples and the "variety check" set (modern ads, college
        // mail, verification emails and their scam copies, written separately from the training
        // set). Leave empty to train on everything.
        public string[] HoldoutSources = { "smoke_main", "smoke_holdout", "seed_variety_check" };

        // Sources that always go into training and never into the validation or test sets.
        // "seed_modern" and "seed_variety" are sets of modern example messages written for this
        // project (verification codes and links, store ads, college marketing, receipts, bills,
        // and the scams that copy them) that the public datasets barely have; see
        // data/SOURCES.md. Grading the model on examples from the same author as its training
        // examples would say little, so they're only used to teach.
        public string[] TrainOnlySources = { "seed_modern", "seed_variety" };

        // Fraction of the remaining records set aside, at random, as the test set ("final exam").
        public double TestFraction = 0.15;

        // Fraction of what's left after that set aside as the validation set ("practice quiz").
        public double ValidationFraction = 0.15;

        // An n-gram must appear in at least this many training messages to become a feature.
        // Things that show up only once are usually noise (a typo, one person's name), and a
        // feature seen in a single message can't teach a general pattern. Use 3 once you have a
        // few thousand records.
        public int MinDf = 3;

        // Upper limit on the number of text features, so memory use stays bounded.
        // (Raised from 60,000 in version 1.4: with the email/text copies there are about twice
        // as many n-grams, and 150,000 scored best in cross-validation.)
        public int MaxFeatures = 150000;

        // Count a repeated n-gram as 1 + ln(count)? See Featurizer, "TWO REFINEMENTS".
        public bool SublinearTf = true;

        // Give every n-gram an emails-only or texts-only copy too? See Featurizer.
        public bool TypeCopies = true;

        // How big a step each weight adjustment takes (called "eta" in LogisticTrainer).
        // Too big: the weights jump around and never settle. Too small: training crawls.
        //
        // These values were picked by "5-fold cross-validation" on the public datasets:
        // split everything EXCEPT the test set into 5 parts, train on 4 and score the 5th, five
        // times over, and keep the settings with the fewest mistakes. The test set wasn't used,
        // so its score is still a fair exam. (Tried: eta 0.5 / 1 / 2, lambda 1e-5 down to 3e-7.)
        public double LearningRate = 2.0;

        // How strongly big weights get pulled back toward 0 (called "lambda"). This fights
        // overfitting: a weight only stays big if lots of examples support it.
        // Bigger = simpler, more cautious model. Early stopping (below) also fights overfitting,
        // which is why this can be small.
        public double L2Lambda = 1e-6;

        // An "epoch" is one full pass over every training example. This is the most it will do.
        public int MaxEpochs = 40;

        // Stop early after this many epochs in a row with no improvement on the validation set.
        public int Patience = 5;

        // "When the app says UNSAFE, it should be right 95% of the time." See ThresholdPicker.
        public double PrecisionTarget = 0.95;

        // "Only 2% of scams should come out SAFE." See ThresholdPicker.
        public double RecallTarget = 0.98;

        // Your best guess at what fraction of a real person's messages are scams (pi).
        // 0.05 means 1 in 20. This is a guess: change it when you know more.
        public double RealWorldScamRate = 0.05;

        // How many times each of your corrections (data/feedback.jsonl) counts in training.
        public int CorrectionCopies = 5;

        // How many times each training-only example (TrainOnlySources) counts.
        // 3 was picked on the first variety check set (before it was folded into training).
        public int TrainOnlyCopies = 3;

        // Add simulated-OCR copies of raw training records? See OcrNoiser.
        public bool AugmentOcr = true;

        // In those copies, the chance that any one character gets an OCR-style mistake.
        public double OcrNoiseRate = 0.04;

        // Learn the metadata weights too, instead of keeping the hand-set ones? Only turn this on
        // once you have plenty of real records WITH metadata (sender, links, auth results).
        public bool TrainMetaWeights = false;

        // Seed for every "random" choice (shuffles, splits, OCR noise). Same seed = exactly the
        // same results every run, which makes changes comparable. Try a different seed to see
        // how much your results depend on luck.
        public long Seed = 42L;
    }

    // The headline numbers from a training run, for showing in the app.
    public class TrainingSummary
    {
        public int TrainCount;        // training records (real ones, without the OCR copies)
        public int ValidationCount;   // validation records
        public int TestCount;         // test records
        public int VocabularySize;    // text features in the vocabulary
        public double TLow;           // the SAFE / CAUTION cut-off
        public double THigh;          // the CAUTION / UNSAFE cut-off
        public double TestAuc;        // AUC on the test set
        public double TestAccuracy;   // accuracy on the test set (UNSAFE counted as scam)
    }
}
