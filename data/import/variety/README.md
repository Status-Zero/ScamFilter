# Variety sets

Example messages written for this project (not collected from real inboxes), to cover the
kinds of everyday messages the public datasets barely contain: store ads, college marketing,
verification codes and links, receipts, school notices, bills, and the scams that copy them.

* `train_*.txt`  -> `seed_variety`        (TRAINING ONLY: never graded)
* `check_*.txt`  -> `seed_variety_check`  (HELD OUT: graded separately; written apart from the
                                           training files, but by the same author, so its score
                                           is optimistic - see SOURCES.md)

Format (one message per block; lines starting with "# " are comments):

    === <label> <E|T>          label 1 = scam, 0 = not a scam; E = email, T = text
    From: Display Name <sender@example.com>     (texts: From: <number or short code>)
    Subject: ...                                 (emails only)
    <blank line>
    body text; a link is written [visible text](https://real.target/)

To add a file's messages to the training data:

    dotnet run --project ScamFilter.Trainer -- import-variety data/import/variety/train_12_new.txt --source seed_variety

(`DatasetTools.ImportVariety` reads the format; `rebuild_dataset.sh` imports every file in order.)
