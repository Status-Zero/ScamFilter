using System;
using System.Collections.Generic;

namespace ScamFilter
{
    /*
     * Training: finds good weights for ScamModel by learning from labeled examples.
     *
     * ============================================================================
     *  STEP 1: MEASURE HOW WRONG A GUESS IS (THE "LOSS")
     * ============================================================================
     * For one example with true label y (1 = scam, 0 = not) and the model's guess p:
     *
     *     loss = -ln(p)          if y = 1   (it's a scam, so we wanted p near 1)
     *     loss = -ln(1 - p)      if y = 0   (it's not, so we wanted p near 0)
     *
     * Written as one formula:  L = -[ y ln(p) + (1 - y) ln(1 - p) ].  This is "log loss".
     *
     *   a scam (y = 1), model says p = 0.99  ->  loss 0.01   confident and right
     *   a scam (y = 1), model says p = 0.50  ->  loss 0.69   unsure
     *   a scam (y = 1), model says p = 0.01  ->  loss 4.61   confident and WRONG
     *
     * Being confidently wrong is punished hard. "Training" means finding the weights that
     * make the average loss over all training examples as small as possible.
     *
     * ============================================================================
     *  STEP 2: NUDGE EVERY WEIGHT DOWNHILL (GRADIENT DESCENT)
     * ============================================================================
     * Picture the loss as a hilly landscape, where moving any weight moves you around on it.
     * We want to reach a low valley. The GRADIENT is, for each weight, the slope of the
     * landscape in that weight's direction: which way is uphill, and how steep. So we take a
     * small step the opposite way (downhill), and repeat thousands of times.
     *
     * For logistic regression, calculus (the chain rule) gives a very simple gradient:
     *
     *     dL/dw_j = (p - y) * x_j          dL/db = (p - y)
     *
     * In plain words:
     *   (p - y) is the ERROR.  A scam (y = 1) guessed at p = 0.3 has error -0.7: too low.
     *   x_j is how much feature j was present in this message.
     *   So each weight moves in proportion to (how wrong we were) x (how involved it was).
     *   Features that weren't in the message (x_j = 0) don't move at all.
     *
     * The update for every feature in the message:
     *
     *     w_j <- w_j - eta * (p - y) * x_j
     *
     * eta (the LEARNING RATE) is the step size. In the example, the error is -0.7, so
     * -eta * (-0.7) * x_j is positive: every word in that scam gets a bit MORE scam weight,
     * and next time those words push the score up. That one line is the whole learning
     * mechanism. A legit message guessed too high does the opposite.
     *
     * ============================================================================
     *  "STOCHASTIC" = ONE EXAMPLE AT A TIME
     * ============================================================================
     * Stochastic gradient descent (SGD) updates after every single example, instead of after
     * averaging over all of them. Each step is a bit noisy, but you get one step per example,
     * so it learns fast.
     *   - One pass over every training example is called an EPOCH.
     *   - The examples are SHUFFLED every epoch. In a fixed order, the weights would always
     *     end each pass leaning toward whatever examples came last.
     *   - eta shrinks a little each epoch: big steps early to get close, small steps later so
     *     it settles into the valley instead of bouncing around in it.
     *
     * ============================================================================
     *  OVERFITTING AND L2 REGULARIZATION
     * ============================================================================
     * With 60k weights and a few thousand examples, the model can MEMORIZE the training set.
     * For example, it could give a huge weight to one scammer's unusual misspelling that only
     * appears in scams. Training loss heads to 0, but that doesn't help on new messages.
     *
     * L2 regularization adds a penalty for big weights, lambda * w^2 / 2 per weight, to the
     * loss. Its slope is lambda * w, so the full update becomes:
     *
     *     w_j <- w_j - eta * ((p - y) * x_j + lambda * w_j)
     *
     * The new term pulls every weight a little toward 0 on every step ("weight decay").
     * A weight only stays big if many examples keep pushing it back up, which is exactly the
     * kind of weight that reflects a real pattern. lambda sets how strong the pull is.
     * (The bias b isn't decayed; it's just the starting score.)
     *
     * ============================================================================
     *  A SPEED TRICK: STORING w AS scale * v
     * ============================================================================
     * The decay touches ALL 60k weights on every step, while the error term only touches the
     * few hundred features actually in the message. Looping over 60k weights per example
     * would be the slowest part of the whole program.
     *
     * So each weight is stored as  w_j = scale * v_j.  Then:
     *   decaying every weight:   w_j <- w_j * (1 - eta*lambda)
     *                            is one multiplication:  scale <- scale * (1 - eta*lambda)
     *   updating feature j:      w_j <- w_j - eta*g*x_j
     *                            becomes                 v_j <- v_j - eta*g*x_j / scale
     * Same math, roughly 100x faster. If scale gets tiny, it's folded back into v so the
     * numbers don't lose precision.
     *
     * ============================================================================
     *  EARLY STOPPING
     * ============================================================================
     * After every epoch we measure the loss on the VALIDATION set, which the model never
     * trains on. Typically it falls for a while, then starts creeping up: the point where the
     * model stops learning general patterns and starts memorizing. We keep a copy of the
     * weights from the epoch with the lowest validation loss, and stop once `Patience` epochs
     * pass without a new best.
     *
     * ============================================================================
     *  METADATA WEIGHTS ARE FROZEN (FOR NOW)
     * ============================================================================
     * Public datasets are mostly bare text with no sender or link info, so there's nothing to
     * learn the metadata weights from. They keep their hand-set values, but still count toward
     * z during training, so the text weights learn whatever the flags don't already explain.
     * Set TrainMetaWeights = true once you have real records with metadata.
     */
    public class LogisticTrainer
    {
        public double LearningRate = 2.0;       // eta at epoch 1. It decays as eta / (1 + 0.1 * (epoch - 1)).
        public double L2 = 1e-6;                // lambda: strength of the pull toward 0
        public int MaxEpochs = 40;              // the most passes over the training data
        public int Patience = 5;                // epochs in a row without a new best before stopping
        public long Seed = 42L;                 // seed for the shuffling, so every run is identical
        public bool TrainMetaWeights = false;   // also learn the metadata weights (see above)

        /*
         * One training example, already turned into numbers, so the expensive text processing
         * happens once instead of once per epoch.
         */
        public class Example
        {
            public readonly SparseVector X;   // text features
            public readonly double[] Flags;   // metadata flags
            public readonly int Y;            // the label: 1 = scam, 0 = not

            public Example(SparseVector x, double[] flags, int y)
            {
                X = x;
                Flags = flags;
                Y = y;
            }
        }

        // Turns records into Examples (text features + flags + label), once, before training.
        public static List<Example> ToExamples(Featurizer featurizer, List<MessageRecord> records)
        {
            List<Example> examples = new List<Example>(records.Count);
            foreach (MessageRecord r in records)
            {
                examples.Add(new Example(featurizer.Transform(r), MetadataFeatures.Compute(r), r.Label));
            }
            return examples;
        }

        /*
         * Log loss for one guess (see the class comment).
         * p is clipped away from exactly 0 and 1, because ln(0) is negative infinity.
         */
        public static double LogLoss(double p, int y)
        {
            double clipped = Math.Min(Math.Max(p, 1e-12), 1.0 - 1e-12);
            return y == 1 ? -Math.Log(clipped) : -Math.Log(1.0 - clipped);
        }

        /*
         * Trains the model in place: when this returns, model.TextWeights and model.Bias hold
         * the weights from the best epoch.
         */
        public void Train(ScamModel model, List<Example> train, List<Example> validation, Action<string> log)
        {
            int d = model.TextWeights.Length;
            double[] v = new double[d];   // text weights, stored as w_j = scale * v_j (see class comment)
            double scale = 1.0;
            double b = 0.0;               // bias
            double[] metaW = model.MetaWeights;

            // The best weights seen so far (judged on validation loss).
            double[] bestW = new double[d];
            double bestB = 0.0;
            double[] bestMeta = (double[]) metaW.Clone();
            double bestValLoss = double.MaxValue;
            int bestEpoch = 0;
            int epochsWithoutImprovement = 0;

            // Instead of shuffling the examples, shuffle a list of their positions.
            int[] order = new int[train.Count];
            for (int i = 0; i < order.Length; i++)
            {
                order[i] = i;
            }
            JavaRandom random = new JavaRandom(Seed);

            log("Training: " + train.Count + " examples, " + d + " text features, "
                + metaW.Length + " metadata flags (" + (TrainMetaWeights ? "learned" : "frozen") + ")");

            for (int epoch = 1; epoch <= MaxEpochs; epoch++)
            {
                random.Shuffle(order);
                double eta = LearningRate / (1.0 + 0.1 * (epoch - 1));   // smaller steps each epoch
                double decay = 1.0 - eta * L2;                             // the L2 shrink factor
                double trainLoss = 0.0;

                for (int n = 0; n < order.Length; n++)
                {
                    Example ex = train[order[n]];

                    // Forward: make a guess with the current weights.
                    double z = scale * ex.X.Dot(v) + b + Dot(metaW, ex.Flags);
                    double p = ScamModel.Sigmoid(z);
                    trainLoss += LogLoss(p, ex.Y);

                    // The error: how far off the guess was, and in which direction.
                    double g = p - ex.Y;

                    // L2: shrink every text weight toward 0, all at once, via the scale.
                    scale *= decay;
                    if (scale < 1e-6)
                    {
                        for (int j = 0; j < d; j++)
                        {
                            v[j] *= scale;
                        }
                        scale = 1.0;
                    }

                    // Gradient step, only on the features this message actually has:
                    //   w_j <- w_j - eta * g * x_j     (written for v_j = w_j / scale)
                    for (int k = 0; k < ex.X.Size; k++)
                    {
                        v[ex.X.Indices[k]] -= eta * g * ex.X.Values[k] / scale;
                    }
                    b -= eta * g;

                    if (TrainMetaWeights)
                    {
                        // Only 20 flags, so plain L2 (no scale trick needed).
                        for (int k = 0; k < metaW.Length; k++)
                        {
                            metaW[k] -= eta * (g * ex.Flags[k] + L2 * metaW[k]);
                        }
                    }
                }
                trainLoss /= Math.Max(1, order.Length);

                // How does this epoch's model do on the validation set (data it never learns from)?
                double valLoss = double.NaN;
                bool improved;
                if (validation.Count == 0)
                {
                    improved = true;   // nothing to compare against, so keep the latest weights
                }
                else
                {
                    valLoss = 0.0;
                    foreach (Example ex in validation)
                    {
                        double z = scale * ex.X.Dot(v) + b + Dot(metaW, ex.Flags);
                        valLoss += LogLoss(ScamModel.Sigmoid(z), ex.Y);
                    }
                    valLoss /= validation.Count;
                    improved = valLoss < bestValLoss - 1e-6;
                }

                // Early stopping bookkeeping: remember the best epoch's weights.
                if (improved)
                {
                    bestValLoss = validation.Count == 0 ? bestValLoss : valLoss;
                    bestEpoch = epoch;
                    for (int j = 0; j < d; j++)
                    {
                        bestW[j] = v[j] * scale;   // store the real weights w_j, not v_j
                    }
                    bestB = b;
                    bestMeta = (double[]) metaW.Clone();
                    epochsWithoutImprovement = 0;
                }
                else
                {
                    epochsWithoutImprovement++;
                }

                log("  epoch " + epoch.ToString().PadLeft(2) + " | train loss " + Format.Fixed(trainLoss, 4)
                    + " | val loss " + (double.IsNaN(valLoss) ? "  n/a " : Format.Fixed(valLoss, 4))
                    + (improved ? "  *" : ""));

                if (epochsWithoutImprovement >= Patience)
                {
                    log("  stopping early: no validation improvement for " + Patience + " epochs");
                    break;
                }
            }

            model.TextWeights = bestW;
            model.Bias = bestB;
            model.MetaWeights = bestMeta;
            log("Kept the weights from epoch " + bestEpoch + " (* = best so far)");
        }

        // Plain dot product: a[0]*b[0] + a[1]*b[1] + ...
        private static double Dot(double[] a, double[] b)
        {
            double sum = 0.0;
            for (int i = 0; i < a.Length; i++)
            {
                sum += a[i] * b[i];
            }
            return sum;
        }
    }
}
