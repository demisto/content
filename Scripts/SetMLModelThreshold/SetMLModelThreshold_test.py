from SetMLModelThreshold import find_threshold


def test_something(mocker):
    y_true = []
    y_pred = []
    # add 7 correct instance of 1st class

    y_true += ['class1']*7
    y_pred += [ {'class1': 0.8, 'class2':0.2 }]*7

    # add 7 correct instance of 2nd class

    y_true += ['class2'] * 7
    y_pred += [{'class2': 0.8, 'class2': 0.2}]*7

    # add 3 incorrect instance of 1st class at lower probability

    y_true += ['class1'] * 3
    y_pred += [{'class1': 0.3, 'class2': 0.7}] * 7

    # add 3 incorrect instance of 1st class at lower probability

    y_true += ['class2'] * 3
    y_pred += [{'class2': 0.3, 'class1': 0.7}] * 7

    find_threshold(y_pred_all_classes= y_pred, y_true= y_true, target_precision=0.75, target_recall = 0)

