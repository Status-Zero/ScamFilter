# Where the training data comes from

`records.jsonl` has 19,152 labeled messages (13,405 not scams, 5,747 scams): 18,129 from seven public collections and 1,023 example messages written for this project. Every public message was converted with the trainer's import commands (see "Rebuilding it" below), so it's in the same record format the app produces.

| Source name in the file | What it is | Records | Label |
|---|---|---:|---|
| `sms_mendeley` | [SMS Phishing Dataset for Machine Learning and Pattern Recognition](https://data.mendeley.com/datasets/f45bkkt8pr) (Mishra and Soni, Mendeley Data, 2022). Text messages labeled ham, spam, or smishing. | 5,570 | smishing = 1, ham and spam = 0, with fixes (see below): 435 scams |
| `nazario_2019` ... `nazario_2025` | [Nazario phishing corpus](https://monkey.org/~jose/phishing/): real phishing emails caught in one person's mailbox, one file per year. | 1,793 | 1 (2 fixed to 0) |
| `phishing_pot` | [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) (rf-peixoto): emails caught by honeypot inboxes, mostly 2023 to 2026. The most modern emails in the data, and the hardest: a honeypot gets scams and pushy marketing side by side. **Labeled for this project** (rules below), because the collection itself calls everything phishing. | 2,241 | 1,909 scams, 332 not scams |
| `clair_fraud` | The CLAIR collection of "Nigerian" advance-fee fraud emails, from the [Phishing Email Curated Datasets](https://zenodo.org/records/8339691) (Champa, Zenodo, 2023). The first 1,200. | 1,200 | 1 |
| `sa_easy_ham`, `sa_easy_ham_2`, `sa_hard_ham` | [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) (2002–2003), the normal-mail ("ham") folders only. *Hard ham* is legit mail that looks spammy: newsletters, receipts, promotions. | 4,091 | 0 |
| `asf_lists` | Apache Software Foundation user mailing lists (activemq, commons, httpd, kafka, maven, solr, spark, tomcat), 2024–2025 archives from [lists.apache.org](https://lists.apache.org). Up to 75 messages per list per month. | 1,734 | 0 |
| `trec07_ham` | Normal mail from the TREC 2007 Public Spam Corpus, from the same curated Zenodo set. At most 25 per sender domain, and no mailing-list traffic, so it adds variety instead of one list's threads. | 1,500 | 0 (3 fixed to 1) |
| `seed_modern` | 143 modern example texts and emails: verification codes, delivery and bank texts, receipts and security emails from real companies' own domains, and the modern scams that copy them. **Training only.** | 143 | 86 legit, 57 scam |
| `seed_variety` | 697 example messages for variety (see "The variety sets" below): store ads and rewards, verification codes and links, password resets, receipts, bills, college admissions and financial-aid mail, school systems, job and work mail, newsletters, personal mail, and the scams that copy each kind. **Training only.** Written in `import/variety/train_*.txt`. | 697 | 422 legit, 275 scam |
| `seed_variety_check` | 114 more example messages, written last, with brands, schools and wording the training files don't use. **Never trained on:** part of the "generalization check" in the training report. In `import/variety/check_*.txt`. | 114 | 70 legit, 44 scam |
| `smoke_main`, `smoke_holdout` | 69 modern example messages (US toll texts, delivery scams, 2FA codes, receipts). **Never trained on.** | 69 | both |

"Training only" sources are never in the validation or test set (`TrainingSettings.TrainOnlySources`), and each of their messages counts 3 times in training (`TrainOnlyCopies`).

## Licenses: read this before sharing a build

The data, and the model trained on it, carry the terms of the collections:

- **Phishing Pot is CC BY-NC 4.0: non-commercial use only, with credit.** A build of ScamFilter whose model learned from it can be shared for free, with credit, but not sold. To make a version you can sell, rebuild without the `phishing_pot` import and retrain.
- The Zenodo curated datasets (`clair_fraud`, `trec07_ham`) are CC BY 4.0: free to use with credit. The TREC 2007 corpus they repackage was first released for research use.
- Check the Mendeley, SpamAssassin, Nazario and Apache pages for their own terms.

## How the data was labeled and cleaned

### The rule: is it a scam?

ScamFilter's rule is that **marketing spam is not a scam**. A message is a scam (1) when it tries to get money, information, or access through a lie. In practice, for labeling:

| Rule | Scam (1) when it... | Examples |
|---|---|---|
| S1 | impersonates a company, service, or institution | fake PayPal/bank/Microsoft/USPS alerts, fake "your mailbox is full" |
| S2 | offers a prize, reward, refund, or payout that isn't real | "you've been selected for a $1,000 gift card, pay shipping" |
| S3 | asks for money or information under a false story | inheritance and "next of kin" letters, fake jobs, loan fees, romance |
| S4 | shows a fake crypto or investment balance, or a fake airdrop | "your account has +28,282$", "claim 500 BNB" |
| S5 | is extortion | "I recorded you through your camera, pay in Bitcoin" |
| S6 | is a fake person, fake news, or a bogus device | "Anna, 23, wants to chat", celebrity advertorials, fuel and power "savers" |
| S7 | is a fake document, voicemail, shared file, or receipt | "Invoice.pdf was shared with you, sign in to view" |

**Not a scam (0):** ads, newsletters, and notifications for real products and services, with no fake win and no impersonation, however pushy they are. A real store's sweepstakes with official rules is 0; "you were chosen, pay $4.95 shipping" is 1.

**Not graded (left out of the data):** messages where reasonable people would disagree, so any label would be a coin flip the model gets blamed for: unclear ones, other languages, casino and gambling promotions (but a casino email claiming you already won stays 1), dating and adult promotions (but a fake person writing to you stays 1), health, supplement, weight-loss and sexual-performance promotions, online pharmacies, IPTV, and shops for criminal tools. This is a real limit: the model wasn't graded on these kinds of message, so it has no measured accuracy on them.

### Phishing Pot

Near-identical emails were grouped into campaigns (word-overlap clustering), each campaign was read against the rules above, and at most 3 emails per campaign were kept, so no single blast dominates. The labels are in `import/phishing_pot_labels.tsv` (file name, label, campaign). Honeypot addresses and the owner's names were replaced with `you` / `you@example.com` (`--scrub`).

### Label fixes

Public labels have mistakes, and the model is only as good as its answer key. Label fixes are in `import/label_fixes.tsv`: each line is a source, the new label (0, 1, or x = leave out), a pattern, and the reason. Every fix applies to **every** message the pattern matches, both directions, not just to the one that caught the eye. 73 labels changed in all:

- **SMS spam vs. scam.** The SMS set labels the same kind of message both ways ("Want a new Video Phone?" is smishing, "Do you want a new video handset?" is spam). Phone-contract, loan, contest-entry, chat-line and property ads were set to 0 by the rule above; texts that bait a premium-rate call ("Thanks for your ringtone order... call 09065...", "missed call alert") or fake a win were set to 1. Before that, spam messages matching `import/sms_scam_patterns.txt` were imported as scams (30), and near-duplicates with conflicting labels got their group's majority label (`fix-conflicts`: 19 groups, 24 labels).
- **Mislabeled emails.** 2007 MySpace phishing in the TREC "ham", two real Honeynet mailing-list posts in the Nazario phishing mailbox, pharmacy and email-list spam in the fraud set (left out: not graded).
- **How they were found.** Mostly "confident learning": train with 5-fold cross-validation, list the messages the model gets very wrong (scored above 0.8 but labeled 0, or below 0.2 but labeled 1), and read each one against the rules. That only finds mistakes the model disagrees with, so it slightly favors the model. That's why the training report numbers below are also given with the original labels.

### Other cleaning

- **Duplicates removed** when importing, so the same message can't land in both training and test. Near-duplicates (the same campaign or template with small changes) are kept, but grouped by `NearDuplicates`, and a group always goes to one side of the train/validation/test split.
- **Privacy.** Names and addresses of the corpus owners were replaced, and mailing-list senders were anonymized (`--anonymize`).
- **Hidden text dropped.** Email HTML is read the way a reader sees it: text hidden with `display:none`, zero-size fonts, or white-on-white is thrown away (see `EmlImporter.RemoveHiddenElements`).
- **Mailing-list footers cut** ("To unsubscribe, e-mail..."), so the model can't learn "has a list footer = safe".
- Placeholder messages and messages under 20 characters were skipped.

## The variety sets

The public data is old or narrow: most normal emails are from 2002 or from software mailing lists, and there are almost no modern legitimate texts. The first models called nearly every verification code and genuine company email a scam, because in the training data that wording only ever appeared in phishing.

`import/variety/` fills that gap with example messages written for this project: 697 for training, across retail ads and rewards, verification codes and links, password resets and sign-in alerts, receipts, shipping and bills, subscriptions and renewals, college admissions marketing, financial aid, testing, school systems, jobs and payroll, newsletters, community and personal mail. Each kind comes with the scams that copy it (fake scholarships, FAFSA "holds", gift-card requests from a "principal", fake renewals with a phone number to call, fake shops, task-job scams...), so the model learns the difference instead of learning "college = safe".

Then 114 more were written last, with different brands, schools and wording, and held out as `seed_variety_check`. (A first check set was used once, to choose `TrainOnlyCopies`, then moved into training as `train_07`/`train_08` and replaced by a freshly written one.)

**The caveat:** the same author wrote the training and the check messages, in a similar style, so the check score is optimistic. Real messages are the only honest test of modern messages. Marking real results in the app (**This is a scam** / **This is safe**) adds them to `feedback.jsonl`, where each counts 5 times in training.

## How well it does (the built-in model, version 1.5.4)

From `model/training_report.txt`: a test set of 2,720 messages the model never trained on (15%, split by near-duplicate group).

| | Texts | Emails |
|---|---|---|
| Accuracy at a 50% cut-off | **97.3%** (22 of 815 wrong) | **98.3%** (32 of 1,905 wrong) |
| The same, with the source datasets' original labels (no label fixes) | 96.6% | 98.3% |
| Scams caught (not called Safe) | 98.2% (56 of 57) | 99.1% (736 of 743) |
| 5-fold cross-validation (used to choose the settings) | 97.6% | 98.0% |
| Variety check (114 examples, never trained on; optimistic, see above) | 91.7% (36) | 85.9% (78) |

Overall AUC 0.997. On the test set, 3 of 1,920 legit messages (0.16%) were called *Unsafe*, and 8 of 800 scams (1%) were called *Safe*.

**The goal was 99.5%, and this is short of it.** Where the misses are:
- Texts: most of the cross-validation misses are UK premium-rate marketing texts from the 2000s that sit right on the spam/scam line. Even after the label fixes, near-identical texts can only be read both ways.
- Emails: in cross-validation the honeypot set (`phishing_pot`) has about 6% errors, the other email sources about 1.2%. Its scams often carry an unrelated newsletter as their body ("hash-busting"), or no body at all, and its marketing looks just like the scams next to it.
- Modern everyday email: short money notices ("Your direct deposit arrived", "Payment confirmation") still get flagged, because in the public data, dollar amounts mostly come from scams. More real examples is the fix.

## Rebuilding it

`import/rebuild_dataset.sh` runs every import, fix and example set in the right order. From the project folder, in Git Bash or WSL, after building the trainer once:

```
dotnet build ScamFilter.Trainer -c Release
bash data/import/rebuild_dataset.sh <datasets folder> <phishing_pot\email folder> <output folder>
```

The script's comments list the files the datasets folder needs. It rebuilds this exact `records.jsonl` (checked byte for byte). Copy the result over `data/records.jsonl`, then train (`dotnet run --project ScamFilter.Trainer`).

The steps, in order: the SMS import (with `sms_scam_patterns.txt`, then `fix-conflicts`), Nazario 2019 to 2025, the SpamAssassin ham folders, the Apache lists, Phishing Pot (with `phishing_pot_labels.tsv`), the CLAIR fraud set, TREC 2007 ham, `fix-labels` with `label_fixes.tsv`, the `import-variety` files (`train_*` as `seed_variety`, then `check_*` as `seed_variety_check`), and finally `seed_modern.jsonl`, appended as-is.
