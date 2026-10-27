using System;
using System.Collections.Generic;
using System.Text;

namespace ScamFilter
{
    /*
     * Makes OCR-style copies of raw training records. (OCR = optical character recognition:
     * the software that reads the text out of a screenshot. It makes typical mistakes.)
     *
     * ============================================================================
     *  WHY: SHORTCUT LEARNING
     * ============================================================================
     * A model learns whatever separates scams from legit messages most easily, even if
     * that's not what you meant. Suppose most scam examples came from screenshots people
     * posted online, while most legit examples were raw text exported from your own phone.
     * Then "this text has OCR typos in it" would separate the two piles very well, and the
     * model would learn "OCR typos = scam". It would score great on a test set built the
     * same way, then flag every screenshot a real user shares.
     *
     * The fix is to make both labels show up in both channels. This class takes records that
     * are already labeled, roughs up their text the way OCR would, and adds them as extra
     * training examples. That's called DATA AUGMENTATION: making more training data from data
     * you already have, without changing what the label should be.
     *
     * Only the training set gets these copies. Validation and test must stay real data, or
     * they'd stop telling you how the model does on real messages.
     *
     * Mistakes simulated: l -> 1 or I,  i/I/1 -> l,  o <-> 0,  m <-> rn,  w -> vv,  e <-> c,
     * S -> 5, a dropped space (two words merge), and a line break becoming a space.
     */
    public class OcrNoiser
    {
        private readonly JavaRandom random;
        private readonly double rate;

        // rate = the chance that any one character gets a mistake (0.04 = 4%).
        public OcrNoiser(long seed, double rate)
        {
            random = new JavaRandom(seed);
            this.rate = rate;
        }

        // A copy of the record as if it had come from a screenshot. The original isn't changed.
        public MessageRecord NoisyCopy(MessageRecord original)
        {
            MessageRecord c = original.Copy();

            // A screenshot shows a link's TEXT ("Click here", "paypal.com"), never where it
            // really goes. So the link text moves into the visible body and the targets are gone.
            StringBuilder visible = new StringBuilder(c.BodyText);
            foreach (MessageRecord.UrlRef u in c.Urls)
            {
                if (u.Display.Length > 0 && c.BodyText.IndexOf(u.Display, StringComparison.Ordinal) < 0)
                {
                    visible.Append('\n').Append(u.Display);
                }
            }
            c.Urls = new List<MessageRecord.UrlRef>();
            c.Subject = Noise(c.Subject);
            c.BodyText = Noise(visible.ToString());
            c.ImageText = Noise(c.ImageText);

            // Everything else a screenshot can't show becomes unknown.
            c.Spf = "";
            c.Dkim = "";
            c.Dmarc = "";
            c.ReplyTo = "";
            c.DomainAgeDays = -1;
            c.SenderIsContact = null;
            c.UserHasReplied = null;
            if (c.IsEmail())
            {
                c.Sender = "";   // email apps usually show the display name, not the address
            }
            c.Channel = "ocr_sim";   // "simulated OCR", so reports can tell these apart
            return c;
        }

        // Walks through the text and, for each character, makes a mistake with probability `rate`.
        private string Noise(string text)
        {
            if (text == null)
            {
                return "";
            }
            StringBuilder output = new StringBuilder(text.Length + 8);
            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (random.NextDouble() >= rate)
                {
                    output.Append(c);   // no mistake on this character (the usual case)
                    i++;
                    continue;
                }
                if (c == 'r' && i + 1 < text.Length && text[i + 1] == 'n')
                {
                    output.Append('m');   // "rn" read as "m" (they look alike in many fonts)
                    i += 2;
                    continue;
                }
                switch (c)
                {
                    case 'l':
                        output.Append(random.NextBoolean() ? '1' : 'I');
                        break;
                    case 'I':
                    case 'i':
                    case '1':
                        output.Append('l');
                        break;
                    case 'o':
                    case 'O':
                        output.Append('0');
                        break;
                    case '0':
                        output.Append('O');
                        break;
                    case 'm':
                        output.Append("rn");
                        break;
                    case 'w':
                        output.Append("vv");
                        break;
                    case 'e':
                        output.Append('c');
                        break;
                    case 'c':
                        output.Append('e');
                        break;
                    case 'S':
                        output.Append('5');
                        break;
                    case ' ':
                        break;                // the space is lost, so two words merge
                    case '\n':
                        output.Append(' ');   // two lines merge
                        break;
                    default:
                        output.Append(c);     // characters OCR rarely confuses stay as they are
                        break;
                }
                i++;
            }
            return output.ToString();
        }
    }
}
