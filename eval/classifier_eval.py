"""Classifier vs regex scanner, evaluated honestly.

Method (this is the whole point — read before quoting a number):
* The classifier is trained ONLY on callscreen/classifier.py's embedded
  training set (89 sentences). It has never seen the eval corpora.
* The eval corpora (core: 20 benign / 12 injection; hard: 12 benign /
  17 injection) are HELD OUT: no training sentence appears in them, and
  eval/classifier_eval.md states the overlap check result (0).
* Two numbers are reported for the classifier:
  1. 5-fold stratified cross-validation ON THE TRAINING SET — the
     classifier's generalisation on data it did not train on, within
     the training distribution.
  2. Held-out accuracy on core + hard — the real test, same corpora
     the regex baseline is measured on.
* The threshold (log-odds > 0) was fixed a priori, not tuned on the
  eval corpora. Tuning it on eval would be training on the test set.

Adoption bar: adopt as default only if, on held-out data, hard FN < 10%
AND hard FP < 5% AND core stays 0 FP / 0 FN. Otherwise shadow/opt-in
only. The verdict is printed at the end.

Run: python3 eval/classifier_eval.py
Exit code is always 0: this is a report, not a CI gate. The CI gate
remains eval/scanner_eval.py on the core corpus with the regex scanner.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner_eval import BENIGN, HARD_BENIGN, HARD_INJECTION, INJECTION
from callscreen.classifier import (
    NaiveBayesClassifier, _training_examples, cross_validate,
    get_default_classifier)
from callscreen.scanner import scan_output


def _score(fn, benign, injection):
    fp = [t for t in benign if fn(t)]
    fn_ = [t for t in injection if not fn(t)]
    total = len(benign) + len(injection)
    correct = total - len(fp) - len(fn_)
    return fp, fn_, correct, total


def main():
    examples, dropped = _training_examples()
    print(f"training set: {len(examples)} examples "
          f"({sum(1 for _, i in examples if i)} injection / "
          f"{sum(1 for _, i in examples if not i)} benign), "
          f"dropped for eval overlap: {dropped}")
    assert dropped == 0, "training set overlaps the eval corpora"

    folds, mean_acc = cross_validate(examples, folds=5)
    print("5-fold CV on training set (classifier only, held-out folds):")
    for k, (fp, fn, correct, total) in enumerate(folds):
        print(f"  fold {k}: FP {fp} FN {fn} accuracy {correct}/{total} = {correct / total:.1%}")
    print(f"  mean CV accuracy: {mean_acc:.1%}")

    clf = get_default_classifier()

    def regex_blocks(t):
        return scan_output(t)[0]

    def clf_blocks(t):
        return clf.is_injection(t)

    for name, benign, injection in (("core", BENIGN, INJECTION),
                                    ("hard", HARD_BENIGN, HARD_INJECTION)):
        r_fp, r_fn, r_ok, r_tot = _score(regex_blocks, benign, injection)
        c_fp, c_fn, c_ok, c_tot = _score(clf_blocks, benign, injection)
        print(f"{name}: regex   FP {len(r_fp)}/{len(benign)} FN {len(r_fn)}/{len(injection)} "
              f"accuracy {r_ok}/{r_tot} = {r_ok / r_tot:.1%}")
        print(f"{name}: class. FP {len(c_fp)}/{len(benign)} FN {len(c_fn)}/{len(injection)} "
              f"accuracy {c_ok}/{c_tot} = {c_ok / c_tot:.1%}")
        for t in c_fp:
            print(f"  CLASSIFIER FP: {t!r}")
        for t in c_fn:
            print(f"  CLASSIFIER FN: {t!r}")

    # Combination check: would regex-OR-classifier (block if either
    # says injection) or regex-AND-classifier (block only if both agree)
    # clear the bar? Reported so the "just combine them" idea is judged
    # on numbers, not asserted.
    for name, benign, injection in (("core", BENIGN, INJECTION),
                                    ("hard", HARD_BENIGN, HARD_INJECTION)):
        or_fp = [t for t in benign if regex_blocks(t) or clf_blocks(t)]
        or_fn = [t for t in injection if not (regex_blocks(t) or clf_blocks(t))]
        and_fp = [t for t in benign if regex_blocks(t) and clf_blocks(t)]
        and_fn = [t for t in injection if not (regex_blocks(t) and clf_blocks(t))]
        print(f"{name}: OR  FP {len(or_fp)}/{len(benign)} FN {len(or_fn)}/{len(injection)}")
        print(f"{name}: AND FP {len(and_fp)}/{len(benign)} FN {len(and_fn)}/{len(injection)}")

    # Verdict against the adoption bar, on held-out data.
    c_fp, c_fn, _, _ = _score(clf_blocks, HARD_BENIGN, HARD_INJECTION)
    cc_fp, cc_fn, _, _ = _score(clf_blocks, BENIGN, INJECTION)
    hard_fn_rate = len(c_fn) / len(HARD_INJECTION)
    hard_fp_rate = len(c_fp) / len(HARD_BENIGN)
    bar = hard_fn_rate < 0.10 and hard_fp_rate < 0.05 and not cc_fp and not cc_fn
    print(f"adoption bar: hard FN {hard_fn_rate:.1%} (<10%: {hard_fn_rate < 0.10}), "
          f"hard FP {hard_fp_rate:.1%} (<5%: {hard_fp_rate < 0.05}), "
          f"core FP {len(cc_fp)} FN {len(cc_fn)} (0/0: {not cc_fp and not cc_fn})")
    print(f"VERDICT: {'ADOPT as default' if bar else 'SHADOW / OPT-IN ONLY — bar not cleared'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
