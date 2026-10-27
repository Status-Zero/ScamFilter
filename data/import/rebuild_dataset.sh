#!/bin/bash
# Rebuilds data/records.jsonl from the downloaded public datasets and the project's own example sets.
# (See data/SOURCES.md for what each dataset is and where to download it.)
#
#   bash data/import/rebuild_dataset.sh <datasets folder> <phishing_pot email folder> <output folder>
#
# Run it from the project folder, in Git Bash or WSL, after building the trainer once
# (dotnet build ScamFilter.Trainer -c Release). The datasets folder must hold:
#   mendeley_sms/extracted/Dataset_5971.csv
#   nazario/phishing-2019 ... phishing-2025
#   spamassassin/20030228_easy_ham, 20030228_easy_ham_2, 20030228_hard_ham
#   asf/*.mbox
#   curated/Nigerian_Fraud.csv, curated/TREC_07.csv
# The result is <output folder>/data/records.jsonl. Copy it over data/records.jsonl and train.
set -e
D=$(cd "$1" && pwd)
POT=$(cd "$2" && pwd)
P=$(pwd)
OUT=$3
T="dotnet $P/ScamFilter.Trainer/bin/Release/net10.0/ScamFilter.Trainer.dll"
rm -rf "$OUT" && mkdir -p "$OUT/data"
cp "$P/data/import/smoke_records.jsonl" "$OUT/data/records.jsonl"   # the 69 smoke-test records
cd "$OUT"
$T import-csv $D/mendeley_sms/extracted/Dataset_5971.csv --source sms_mendeley --map ham=0,spam=0,smishing=1 --type text \
   --scam-patterns "$P/data/import"/sms_scam_patterns.txt --scam-patterns-for spam | tail -1
$T fix-conflicts --source sms_mendeley --similarity 0.6 | tail -1
for y in 2019 2020 2021 2022 2023 2024 2025; do
  $T import-mbox $D/nazario/phishing-$y --label 1 --source nazario_$y --scrub "jose=you,monkey.org=example.com,monkey=example,nazario=" | tail -1
done
for c in easy_ham easy_ham_2 hard_ham; do
  $T import-dir $D/spamassassin/20030228_$c --label 0 --source sa_$c --anonymize \
     --scrub "spamassassin.taint.org=example.com,taint.org=example.com,jmason.org=example.com" | tail -1
done
for f in $D/asf/*.mbox; do $T import-mbox $f --label 0 --source asf_lists --anonymize --limit 75 --scrub "apache=project,apache.org=example.org" | tail -1; done
# ---- new in 1.4 ----
POTSCRUB="phishing@pot-f-p=you@example.com,phishing@pot-fp=you@example.com,phishing@pot=you@example.com,honey@pot=you@example.com,phish@pot=you@example.com,wpx@protonmail.com=you@example.com,garyb59@protonmail.com=you@example.com,rodrigo-f-p@hotmail.com=you@example.com,rodrigo-fp@hotmail.com=you@example.com,merciayanmact@hotmail.com=you@example.com,rodrigo-f-p=you,rodrigo-fp=you,rodrigofp=you,rf-peixoto=you,rodrigo=you,peixoto=,merciayanmact=you,wpx=you,corvo=you,phishing=you,Enviado=Sent,Assunto=Subject"
$T import-dir $POT --source phishing_pot --labels "$P/data/import"/phishing_pot_labels.tsv --scrub "$POTSCRUB" | tail -1
$T import-csv $D/curated/Nigerian_Fraud.csv --source clair_fraud --type email --text-column body --label-column label \
   --subject-column subject --sender-column sender --map 1=1 --limit 1200 | tail -1
$T import-csv $D/curated/TREC_07.csv --source trec07_ham --type email --text-column body --label-column label \
   --subject-column subject --sender-column sender --map 0=0 --anonymize --per-sender-limit 25 --limit 1500 \
   --exclude-subject '^\s*((re|fwd?|aw|fw)\s*:\s*)*\[|^\s*(re|aw)\s*:|svn commit|build status|^\s*\[' | tail -1
$T fix-labels "$P/data/import"/label_fixes.tsv | tail -40
# ---- the variety sets: train_* teach (seed_variety), check_* are held out (seed_variety_check) ----
for f in "$P/data/import"/variety/train_*.txt; do $T import-variety $f --source seed_variety | tail -1; done
for f in "$P/data/import"/variety/check_*.txt; do $T import-variety $f --source seed_variety_check | tail -1; done
# ---- the other example sets (appended as-is) ----
for f in "$P/data/import"/seed_*.jsonl; do cat $f >> data/records.jsonl; done
wc -l data/records.jsonl
