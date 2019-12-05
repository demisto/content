import json

from SetMLModelThreshold import find_threshold


def test_main(mocker):
    y_true = []
    y_pred_all_classes = []
    # 7 correct instnaces of each class
    y_true += ['1']*7
    y_true += ['2']*7
    y_pred_all_classes += [{'1': 0.8, '2': 0.2}]*7
    y_pred_all_classes += [{'1': 0.2, '2': 0.8}]*7

    # 3 incorrect instnaces of each class at lower confidence
    y_true += ['1']*3
    y_true += ['2']*3
    y_pred_all_classes += [{'1': 0.3, '2': 0.7}]*3
    y_pred_all_classes += [{'1': 0.7, '2': 0.3}]*3
    target_precision = 0.8
    target_recall  = 0
    find_threshold(json.dumps(y_true), json.dumps(y_pred_all_classes), target_precision, target_recall)