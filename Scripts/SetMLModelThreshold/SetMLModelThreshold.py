import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score

from CommonServerPython import *


def binarize(arr, threshold):
    return np.where(arr >= threshold, 1.0, 0)


def calculate_confusion_matrix(y_true, y_pred,  y_pred_per_class, threshold):
    indices_higher_than_threshold = set()
    for i, y in enumerate(y_pred):
        if y_pred_per_class[y][i] >= threshold:
            indices_higher_than_threshold.add(i)

    y_true_at_threshold = [y for i,y in enumerate(y_true) if i in indices_higher_than_threshold]
    y_pred_at_threshold = [y for i,y in enumerate(y_pred) if i in indices_higher_than_threshold]
    data = {'y_true': y_true_at_threshold,
        'y_pred': y_pred_at_threshold,

        }
    df = pd.DataFrame(data, columns=['y_true', 'y_pred'])
    csr_matrix = pd.crosstab(df['y_true'], df['y_pred'], rownames=['True'], colnames=['Predicted'], margins=True)
    return csr_matrix


def generate_metrics_df(y_true, y_true_per_class, y_pred, y_pred_per_class, threshold):
    df = pd.DataFrame(columns=['Class', 'Precision', 'Recall', 'Classified Correctly', 'Coverage', 'Total'])
    for class_, y_pred_class in y_pred_per_class.items():
        y_true_class = y_true_per_class[class_]
        y_pred_class_binary = binarize(y_pred_class,threshold)
        precision = precision_score(y_true=y_true_class, y_pred= y_pred_class_binary)
        recall = recall_score(y_true=y_true_class, y_pred= y_pred_class_binary)
        classified_correctly = sum(1 for y_true_i, y_pred_i in zip (y_true_class, y_pred_class_binary) if y_true_i == 1 and y_pred_i == 1)
        above_thresh = sum(1 for i, y_true_i in enumerate(y_true_class) if y_true_i == 1 and any(y_pred_per_class[c][i] >= threshold for c in y_pred_per_class))
        total = sum(y_true_class)
        df = df.append({'Class': class_,
                        # 'Precision': '{:.2f}%'.format(precision*100),
                        # 'Recall' :'{:.2f}%'.format(recall*100),
                        'Precision' : precision,
                        'Recall' : recall,
                        'Classified Correctly': classified_correctly,
                        'Coverage': above_thresh,
                        'Total': total}, ignore_index=True)
    df = df.append({'Class': 'All',
                        'Precision': df["Precision"].mean(),
                        'Recall' : df["Recall"].mean(),
                        'Classified Correctly': df["Classified Correctly"].sum(),
                        'Coverage': df["Coverage"].sum(),
                        'Total': df["Total"].sum()}, ignore_index=True)
    df['Precision'] = df['Precision'].apply(lambda precision: '{:.2f}%'.format(precision*100))
    df['Recall'] = df['Recall'].apply(lambda recall: '{:.2f}%'.format(recall*100))

    explanation = [
        'Precision - Binary precision of the class (TP / TP + FP)',
        'Recall - Binary recall of the class (TP// TP + FN)',
        'Classified Correctly - ￿￿Number of mails from the class which were classified correctly',
        'Coverage Number of mails from the class which were given any prediction (above threshold)',
        'Total - The number of mails from class (above and below threshold)',

    ]

    return df, explanation




def output_report(y_true, y_true_per_class, y_pred,  y_pred_per_class, threshold):
    csr_matrix_at_threshold = calculate_confusion_matrix(y_true, y_pred,  y_pred_per_class, threshold)
    metrics_df, metrics_explanation = generate_metrics_df(y_true, y_true_per_class, y_pred, y_pred_per_class, threshold)
    print(metrics_df)
    return threshold, csr_matrix_at_threshold


def find_threshold( y_true_str, y_pred_str, target_precision, target_recall):
    y_true = conver_str_to_json(y_true_str,'yTrue')
    y_pred_all_classes = conver_str_to_json(y_pred_str,'yPred')
    labels = sorted(set(y_true + y_pred_all_classes[0].keys()))
    n_instances = len(y_true)
    y_true_per_class = {class_ : np.zeros(n_instances) for class_ in labels}
    for i, y in enumerate(y_true):
        y_true_per_class[y][i] = 1.0

    y_pred_per_class = {class_ : np.zeros(n_instances) for class_ in labels}
    y_pred =  []
    for i, y in enumerate(y_pred_all_classes):
        predicted_class = sorted(y.items(), key=lambda x: x[1], reverse=True)[0][0]
        y_pred_per_class[predicted_class][i] = y[predicted_class]
        y_pred.append(predicted_class)


    for threshold in np.arange(0.05, 1, 0.05):
        if all(precision_score(y_true_per_class[class_], binarize(y_pred_per_class[class_], threshold))>= target_precision for class_ in labels) and\
                all(recall_score(y_true_per_class[class_], binarize(y_pred_per_class[class_], threshold))>= target_recall for class_ in labels):
            return output_report(np.array(y_true), y_true_per_class, np.array(y_pred),  y_pred_per_class, threshold)

    else:
        return_error('Could not find threshold which satisfies the following conditions :\n\
        1. precision larger or equal than {} for all classes \n\
        2. recall larger or equal than {} for all classes'.format(target_precision, target_recall))










def conver_str_to_json(str_json, var_name):
    try:
        y_true = json.loads(str_json)
    except Exception as e:
        return_error('Exception while reading {} :{}'.format(var_name, e))
    return y_true


def main():
    y_pred_all_classes = demisto.args()["yPred"]
    y_true = demisto.args()["y_true"]
    target_precision =  float(demisto.args()["targetPrecision"]) if "targetPrecision" not in  demisto.args() else 0
    target_recall = float(demisto.args()["targetRecall"]) if "targetRecall" not in  demisto.args() else 0
    find_threshold(y_pred_all_classes,y_true, target_precision, target_recall )






if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
