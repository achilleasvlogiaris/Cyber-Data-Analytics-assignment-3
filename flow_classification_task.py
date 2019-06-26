import pandas as pd
import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from sklearn.metrics import confusion_matrix
import random
import sys
import warnings
if not sys.warnoptions:
    warnings.simplefilter("ignore")

def read_dataset():
    columns = ['DateTime', 'Duration', 'Protocol', 'Source', 'Direction', 'Destination', 'Flag', 'Tos', 'Packet', 'Bytes', 'Flows', 'Label']
    lst = []
    with open('capture20110818.pcap.netflow.labeled') as fp:
        for i, j in enumerate(fp):
            k = []
            if i != 0:
                data = j.split("\t")
                if len(data) >= 13:
                    for d in data:
                        d.strip()
                        if len(d) == 0:
                            k = data.remove(d)
                if k:
                    lst.append(k)
                else:
                    lst.append(data)
    dataset = pd.DataFrame(lst, columns=columns)
    return dataset


def remove_bgkrd(dataset):
    dataset = dataset.loc[dataset.Label != 'Background\n']
    # remove Nan with 0
    dataset = dataset.fillna(0)
    # convert columns to int
    dataset.Tos = dataset.Tos.astype(int)
    dataset['Packet'] = dataset['Packet'].astype(int)
    dataset['Bytes'] = dataset['Bytes'].astype(int)
    dataset.Flows = dataset.Flows.astype(int)
    # Drop zero labels  (we have only two types of labels)
    dataset = dataset.loc[dataset.Label != 0]

    # convert DateTime into datatime  and set DateTime as indexes
    dataset.DateTime = pd.to_datetime(dataset.DateTime)
    dataset = dataset.set_index(dataset.DateTime)

    return dataset


def port(dataset):
    if len(dataset.split(':')) > 1:
        return dataset.split(':')[1]
    else:
        return ' '


def extract_ports(dataset):
    dataset['SourceIP'] = dataset['Source'].apply(lambda x: x.split(':')[0])
    dataset['SourcePort'] = dataset['Source'].apply(lambda y: port(y))
    dataset['DestIP'] = dataset['Destination'].apply(lambda x: x.split(':')[0])
    dataset['DestPort'] = dataset['Destination'].apply(lambda y: port(y))

    return dataset


def bc_lus(dataset):
    begin = dataset.index[0]
    end = dataset.index[0]
    # the new aggregate dataset
    new_dataset = pd.DataFrame()
    # while loop till end
    while begin in dataset.index:
        # take two minutes time window
        end = begin + datetime.timedelta(minutes=2)
        window = dataset.loc[(dataset.index >= begin) & (dataset.index <= end)]
        # remaining dataset
        remain = dataset.loc[dataset.index > end]
        # loop for inner time window inside time window
        begin1 = begin
        for i in range(0, 2):
            end1 = begin1 + datetime.timedelta(minutes=1)
            window1 = window.loc[(window.index >= begin1) & (window.index <= end1)]
            # do aggregations
            group = window1.groupby('SourceIP')
            agg = group.aggregate({'Packet': np.sum, 'Bytes': np.sum, 'Flows': np.sum, 'Tos': np.sum})
            agg['Destination'] = window1.groupby('SourceIP').Destination.nunique()
            agg['SourcePorts'] = window1.groupby('SourceIP').SourcePort.nunique()
            agg['DestPorts'] = window1.groupby('SourceIP').DestPort.nunique()
            new_dataset = new_dataset.append(agg, ignore_index=False)
            begin1 = end1
        if len(remain) == 0:
            break
        else:
            begin = remain.index[0]

    # reset index in the new dataset
    new_dataset = new_dataset.reset_index()
    return new_dataset

def label(data):
    infected = {'147.32.84.165', '147.32.84.191', '147.32.84.192', '147.32.84.193', '147.32.84.204',
             '147.32.84.205', '147.32.84.206', '147.32.84.207', '147.32.84.208', '147.32.84.209'}
    if data in infected:
        return 1
    else:
        return 0



def adversary(dataset):

    packets_all = []
    bytes_all = []
    row_packet_norm = random.randint(0, 10)
    row_bytes_norm = random.randint(0, 10)
    for index, row in dataset.iterrows():
        if int(row['Label']) == 0:
            packets_all.append(row['Packet'])  # *2
            bytes_all.append(row['Bytes'])  # *2
            row_packet_norm = row['Packet']
            row_bytes_norm = row['Bytes']
        else:
            packets_all.append(row_packet_norm + random.randint(0, 10))
            bytes_all.append(row_bytes_norm + random.randint(0, 10))



    dataset['Packet'] = packets_all
    dataset['Bytes'] = bytes_all

    return dataset



def packet_lvl_clf(dataset, iter):
    # store ips of the new dataset
    ips = dataset.SourceIP
    # drop ips for the final dataset
    final_dataset_packet = dataset.drop('SourceIP', axis=1)
    pd.set_option('display.max_columns', None)


    # ------------------------ UN-COMMENT THIS TWO LINES IN ORDER TO RUN THE ADVERSARY ------------------------
    # advers_dataset = adversary(final_dataset_packet)
    # final_dataset_packet = advers_dataset


    TN = []
    FP = []
    FN = []
    TP = []

    for i in range(iter):
        classifier = RandomForestClassifier()
        x_train, x_test, train_label, test_label = train_test_split(final_dataset_packet, final_dataset_packet['Label'], test_size=0.2)
        x_train = x_train.drop('Label', axis=1)
        x_test = x_test.drop('Label', axis=1)
        smt = SMOTE(random_state=42, ratio=float(0.5))
        balanced_x_train, balanced_train_label = smt.fit_sample(x_train, train_label)
        classifier.fit(balanced_x_train, balanced_train_label)
        predicts = classifier.predict(x_test)
        tn, fp, fn, tp = confusion_matrix(predicts, test_label).ravel()
        TN.append(tn)
        FP.append(fp)
        FN.append(fn)
        TP.append(tp)

    print('True Positive', int(round(np.mean(TP))))
    print('False Positive', int(round(np.mean(FP))))
    print('False Negative', int(round(np.mean(FN))))
    print('True Negative', int(round(np.mean(TN))))
    print('precision:', int(round(np.mean(TP)))/(int(round(np.mean(TP)))+int(round(np.mean(FP)))))
    print('recall', int(round(np.mean(TP)))/(int(round(np.mean(TP)))+int(round(np.mean(FN)))))


def host_lvl_clf(dataset, iter):
    # Group by SourceIP
    new_dataset2 = dataset.groupby('SourceIP')
    new_dataset2 = new_dataset2.sum()
    new_dataset2 = new_dataset2.reset_index()

    new_dataset2['Label'] = new_dataset2['SourceIP'].apply(lambda y: label(y))
    final_dataset_host = new_dataset2.drop('SourceIP', axis=1)
    pd.set_option('display.max_columns', None)


    # ------------------------ UN-COMMENT THIS TWO LINES IN ORDER TO RUN THE ADVERSARY ------------------------
    # advers_dataset_host = adversary(final_dataset_host)
    # final_dataset_host = advers_dataset_host


    TN = []
    FP = []
    FN = []
    TP = []

    for i in range(iter):
        classifier = RandomForestClassifier()
        x_train, x_test, train_label, test_label = train_test_split(final_dataset_host, final_dataset_host['Label'], test_size=0.2)
        x_train = x_train.drop('Label', axis=1)
        x_test = x_test.drop('Label', axis=1)
        smt = SMOTE(random_state=42, ratio=float(0.5))
        balanced_x_train, balanced_train_label = smt.fit_sample(x_train, train_label)
        classifier.fit(balanced_x_train, balanced_train_label)
        predicts = classifier.predict(x_test)
        tn, fp, fn, tp = confusion_matrix(predicts, test_label, labels=[0, 1]).ravel()
        TN.append(tn)
        FP.append(fp)
        FN.append(fn)
        TP.append(tp)

    print('True Positive', int(round(np.mean(TP))))
    print('False Positive', int(round(np.mean(FP))))
    print('False Negative', int(round(np.mean(FN))))
    print('True Negative', int(round(np.mean(TN))))
    print('precision:', int(round(np.mean(TP)))/(int(round(np.mean(TP)))+int(round(np.mean(FP)))))
    print('recall', int(round(np.mean(TP)))/(int(round(np.mean(TP)))+int(round(np.mean(FN)))))




def main():
    dataset = read_dataset()
    dataset = remove_bgkrd(dataset)
    dataset = extract_ports(dataset)

    # --------write--------
    dataset.to_pickle('dataset_augm.pkl')
    # --------read--------
    dataset = pd.read_pickle('dataset_augm.pkl')
    #
    pd.set_option('display.max_columns', None)

    dataset = bc_lus(dataset)

    dataset['Label'] = dataset['SourceIP'].apply(lambda y: label(y))

    # --------write--------
    dataset.to_pickle('bc_dataset_augm.pkl')
    # --------read--------
    dataset = pd.read_pickle('bc_dataset_augm.pkl')
    print("Packet level:")
    print(" ")
    packet_lvl_clf(dataset, 10)
    print(" ")
    print(" ")
    print("Host level:")
    print(" ")
    host_lvl_clf(dataset, 10)

if __name__ == "__main__":
    main()

