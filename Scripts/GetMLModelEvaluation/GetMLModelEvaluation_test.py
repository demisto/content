import json

import pytest

from GetMLModelEvaluation import find_threshold

y_true = []
y_pred = []
# add 7 correct instance of 1st class

y_true += ['class1'] * 7
y_pred += [{'class1': 0.8, 'class2': 0.2}] * 7

# add 7 correct instance of 2nd class

y_true += ['class2'] * 7
y_pred += [{'class2': 0.8, 'class1': 0.2}] * 7

# add 3 incorrect instance of 1st class at lower probability

y_true += ['class1'] * 3
y_pred += [{'class1': 0.3, 'class2': 0.7}] * 3

# add 3 incorrect instance of 1st class at lower probability

y_true += ['class2'] * 3
y_pred += [{'class2': 0.3, 'class1': 0.7}] * 3

# 1 incorrect insance of 1st class at high probability
y_true += ['class1'] * 1
y_pred += [{'class1': 0.1, 'class2': 0.9}] * 1


def test_threshold_found(mocker):
    global y_true, y_pred
    entry = find_threshold(y_pred_str=json.dumps(y_pred),
                           y_true_str=json.dumps(y_true),
                           target_precision=0.65,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.7) < 10 ** -2


def test_threshold_found_2(mocker):
    global y_true, y_pred
    entry = find_threshold(y_pred_str=json.dumps(y_pred),
                           y_true_str=json.dumps(y_true),
                           target_precision=0.6,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0) < 10 ** -2


def test_no_existing_threshold(mocker):
    with pytest.raises(SystemExit):
        find_threshold(y_pred_str=json.dumps(y_pred), y_true_str=json.dumps(y_true), target_precision=1,
                       target_recall=0)
