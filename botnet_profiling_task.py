import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix



def sliding_window(host_data, width):
    start_time = host_data['DateTime']
    diff_list = []
    for i in range(len(host_data)):
        if i == 0:
            difference = 0
        else:
            difference = start_time.iloc[i] - start_time.iloc[i - 1]
            difference = np.ceil(difference.value / 1e6)
        diff_list.append(difference)

    diff_list = pd.Series(diff_list)
    host_data['time'] = diff_list.values

    # keep the hosts in the specified sliding window
    state_list = []
    for i in range(len(host_data)):
        j = i
        state_list.append([])
        temp_list = [host_data['code'].iloc[j]]
        time_sum = 0
        while True:
            try:
                time_sum += diff_list[j + 1]
            except:
                break
            j += 1
            if time_sum <= width:
                temp_list.append(host_data['code'].iloc[j])
            else:
                break
        if len(temp_list) >= 3:
            state_list[i] = temp_list
    host_data['window_states'] = state_list
    return host_data

# apply the n-grams sequencial model


def ngrams(states, n):
    ngrams = []
    for state in states:
        for s in range(len(state)-n+1):
            ngrams.append(state[s:s+n])
    return ngrams


def sorting(grams3_normals):
    ngram_dict = {}
    for gram in grams3_normals:
        grams = str(gram)[1:-1]
        if grams in ngram_dict:
            ngram_dict[grams] += 1
        else:
            ngram_dict[grams] = 1
    sorted_ngrams = sorted(ngram_dict.items(), key=lambda x: x[1], reverse=True)
    sortedgrams_normed = [(i[0], 1.0 * i[1] / len(grams3_normals)) for i in sorted_ngrams]
    return sortedgrams_normed


def fingerprint_matching(train, finger_test, top_n):
    train_n = train[0:top_n]
    freq_train = [pair[1] for pair in train_n]

    test = {pair[0]: pair[1] for pair in finger_test}

    fre_test = []
    for i in range(top_n):
        key = train_n[i][0]
        if key in test:
            fre_test.append(test[key])
        else:
            fre_test.append(0)
    finger_train = np.array(freq_train)
    finger_test = np.array(fre_test)
    distance = sum((np.divide((finger_train-finger_test), (finger_train+finger_test)/2))**2)
    return distance


def evaluation(fmatch_test):

    test_label = np.zeros(len(fmatch_test))
    for i in range(len(fmatch_test)):
            if fmatch_test[i][0] <= fmatch_test[i][1]:
                test_label[i] = 1
            else:
                test_label[i] = 0

    # 1 = infected host, 0 = normal host
    true_label = [1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]

    tn, fp, fn, tp = confusion_matrix(test_label, true_label).ravel()

    print("TP:  ", tp)
    print("FP:  ", fp)
    print("FN:  ", fn)
    print("TN:  ", tn)
    print('precision:', float(tp)/(tp+fp))
    print('recall', float(tp)/(tp+fn))


def main():

    # read pickle files
    discrete = pd.read_pickle('discrete.pkl')
    # picking rain and test host
    train_infected_host = '147.32.84.205'
    train_normal_host = '147.32.84.170'

    # remaining test hosts
    test_hosts = ['147.32.84.165', '147.32.84.191', '147.32.84.192', '147.32.84.193', '147.32.84.204',
                 '147.32.84.208', '147.32.84.206', '147.32.84.207', '147.32.84.209', '147.32.84.134',
                  '147.32.84.164', '147.32.87.36', '147.32.80.9', '147.32.87.11']

    # ---------------- train ----------------
    # fingerprinting the normal host used as train
    train_normal = discrete[(discrete['Source'] == train_normal_host) | (discrete['Destination'] == train_normal_host)]
    train_normal_states = sliding_window(train_normal, width=100)
    train_normal_states = [l for l in train_normal_states['window_states'] if len(l) > 0]
    train_normal_ngrams = ngrams(train_normal_states, 3)
    train_normal = sorting(train_normal_ngrams)

    # fingerprinting the infected host used as train
    train_infected = discrete[(discrete['Source'] == train_infected_host) | (discrete['Destination'] == train_infected_host)]
    train_infected_states = sliding_window(train_infected, width=100)
    train_infected_states = [l for l in train_infected_states['window_states'] if len(l) > 0]
    train_infected_ngrams = ngrams(train_infected_states, 3)
    train_infected = sorting(train_infected_ngrams)

    # ---------------- test ----------------
    fmatch_test = np.zeros((len(test_hosts), 3))

    for index, host in enumerate(test_hosts):
        test_data = discrete[(discrete['Source'] == host) | (discrete['Destination'] == host)]
        test_states = sliding_window(test_data, width=100)
        test_states = [l for l in test_states['window_states'] if len(l) > 0]
        test_ngrams = ngrams(test_states, 3)
        test_fingerprint = sorting(test_ngrams)
        fmatch_test[index][0] = fingerprint_matching(train_infected, test_fingerprint, 10)
        fmatch_test[index][1] = fingerprint_matching(train_normal, test_fingerprint, 10)
    evaluation(fmatch_test)


if __name__ == "__main__":
    main()
