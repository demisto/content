
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

# add 3 incorrect instance of 2nd class at lower probability

y_true += ['class2'] * 3
y_pred += [{'class2': 0.3, 'class1': 0.7}] * 3

# 1 incorrect insance of 1st class at high probability
y_true += ['class1'] * 1
y_pred += [{'class1': 0.1, 'class2': 0.9}] * 1

'''
class 1 precision per threshold:
-------------------------------------------
threshold == 0 (all predictions are 'class1)   ->  TP = 1 + 3 + 7  FP = 3 + 7 -> Precision = 0.63
threshold == 0.7 -> TP = 7  FP = 3  -> Precision = 0.7
threshold == 0.8 -> TP = 7  FP = 0 -> Precision = 1
'''

'''
class 2 precision per threshold:
-------------------------------------------
threshold == 0 (all predictions are 'class2)   ->  TP = 3 + 7  FP = 3 + 7 + 1 -> Precision = 0.63
threshold == 0.7 -> TP = 7  FP = 3 + 1  -> Precision = 0.636
threshold == 0.8 -> TP = 7  FP = 1 -> Precision = 0.875
threshold == 0.9 -> TP = 0  FP = 1 -> Precision = 0
'''


def test_threshold_found_0(mocker):
    global y_true, y_pred
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.7) < 10 ** -2


def test_threshold_found_1(mocker):
    global y_true, y_pred
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.63,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.7) < 10 ** -2


def test_threshold_found_2(mocker):
    global y_true, y_pred
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.7,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.8) < 10 ** -2


def test_threshold_found_3(mocker):
    global y_true, y_pred
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.875,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.8) < 10 ** -2


def test_no_existing_threshold(mocker):
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.9,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.8) < 10 ** -2


def test_predictions_are_correct_and_all_equals_one_prob(mocker):
    y_true = ['class1'] * 7 + ['class2'] * 7
    y_pred = [{'class1': 0.95}] * 7 + [{'class2': 0.95}] * 7
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.6,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.95) < 10 ** -2


def test_predictions_are_correct_and_almost_all_equals_one_prob(mocker):
    y_true = ['class1'] * 7 + ['class2'] * 7
    y_pred = [{'class1': 1}] * 6 + [{'class1': 0.95}] + [{'class2': 1}] * 7
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.6,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.95) < 10 ** -2


def test_plabook_test_simulation(mocker):
    y_pred = [{"spam": 0.9987042546272278}, {"ham": 0.9987037777900696}]
    y_true = ["spam", "ham"]
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.7,
                           target_recall=0)
    assert abs(entry['Contents']['threshold'] - 0.9987037777900696) < 10 ** -2


def test_all_wrong_predictions(mocker):
    y_true = ['class1'] * 7 + ['class2'] * 7
    y_pred = [{'class2': 0.5}] * 7 + [{'class1': 0.5}] * 7
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0.6,
                           target_recall=0)
    assert entry['Contents']['threshold'] >= 0.5


def test_all_wrong_predictions_2(mocker):
    y_true = ['class1'] * 7 + ['class2'] * 7
    y_pred = [{'class2': 0.5}] * 7 + [{'class1': 0.5}] * 7
    entry = find_threshold(y_pred_all_classes=y_pred,
                           y_true=y_true,
                           customer_target_precision=0,
                           target_recall=0)
    assert entry['Contents']['threshold'] >= 0.5
