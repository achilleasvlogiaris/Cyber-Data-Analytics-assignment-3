import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
import numpy as np
from scipy.spatial.distance import cdist
import math
import csv

def read_dataset():
    lines = [line.rstrip('\n') for line in open('capture20110818.pcap.netflow.labeled')]
    columns = ['DateTime', 'Duration', 'Protocol', 'Source', 'Destination', 'Packet', 'Bytes', 'Label']
    data = []
    for line in lines[1:]:
        lists = line.split("\t")
        spl = ' '.join(lists).split()

        data.append([spl[0] + " " + spl[1], spl[2], spl[3],
                     spl[4].split(":")[0], spl[6].split(":")[0], spl[9], spl[10], spl[12]])




    dataset = pd.DataFrame(data, columns=columns)
    dataset = dataset[dataset['Protocol'].isin(['UDP', 'TCP', 'ICMP'])]
    return dataset

def remove_bkgd_flows(dataset):
    # step1: remove background traffic
    dataset_clean = dataset.loc[(dataset['Label'] != "Background")]
    dataset_clean = dataset_clean.reset_index(drop=True)

    # step2: parse dates as datatime
    dataset_clean['DateTime'] = pd.to_datetime(dataset_clean['DateTime'], format='%Y-%m-%d %H:%M:%S', errors='coerce')

    # step3: replace NAN values with zero

    if (dataset.isnull().sum().sum() > 0):
        dataset_clean['Packet'] = dataset_clean['Packet'].fillna(0)
        dataset_clean['Bytes'] = dataset_clean['Bytes'].fillna(0)
        dataset_clean['Duration'] = dataset_clean['Duration'].fillna(0)

    # step4: labels set to binary values, 0 for botnet and 1 for benign
    for index, i in enumerate(dataset_clean['Label']):
        if i == 'Botnet':
            val = 0
        else:
            val = 1
        dataset_clean.set_value(index, 'binLabel', val)


    dataset_clean['Packet'] = dataset_clean['Packet'].astype(int)
    dataset_clean['Bytes'] = dataset_clean['Bytes'].astype(int)
    dataset_clean['Duration'] = dataset_clean['Duration'].astype(float)

    infected_host = '147.32.84.205'
    dataset_infected = dataset_clean.loc[
        (dataset_clean['Source'] == infected_host) | (dataset_clean['Destination'] == infected_host)]
    dataset_infected = dataset_infected.reset_index()

    return dataset_clean, dataset_infected


def visualize(dataset_clean, dataset_infected):
    # investigate one infected host
    # we choose the one with the most flows
    infected_host = '147.32.84.205'

    # ----------- first feature visualization -----------

    # investigate the protocol for the normal hosts
    plt.title('Protocols for normal hosts')
    dataset_normal = dataset_clean.loc[dataset_clean['binLabel'] == 1.0]
    sns.countplot(x="Protocol", data=dataset_normal)
    plt.show()


    # investigate the protocol for the infected host
    plt.title('Protocols for infected host:' + infected_host)
    sns.countplot(x="Protocol", data=dataset_infected)
    plt.show()



    # ----------- second feature visualization -----------( SOS!!!!! infected_dataset != infected!!!!!!!!!!)

    packets = []
    bytes = []
    duration = []

    # add data for normal hosts
    dataset_normal = dataset_clean.loc[dataset_clean['binLabel'] == 1.0]
    packets.append(dataset_normal.Packet.mean())
    bytes.append(dataset_normal.Bytes.mean())
    duration.append(dataset_normal.Duration.mean())


    # add data for botnet hosts
    infected = dataset_clean.loc[dataset_clean['binLabel'] == 0.0]
    packets.append(infected.Packet.mean())
    bytes.append(infected.Bytes.mean())
    duration.append(dataset_normal.Duration.mean())


    labels = ('Legitimate', 'Botnet')

    # construct the dataframes
    packets_frame = {'Label': labels, 'Packets': packets}
    bytes_frame = {'Label': labels, 'Bytes': bytes}
    duration_frame = {'Label': labels, 'Duration': duration}

    packets_frame = pd.DataFrame(packets_frame)
    bytes_frame = pd.DataFrame(bytes_frame)
    duration_frame = pd.DataFrame(duration_frame)

    plt.title('Average number of transmitted packets for different categories')
    sns.barplot(x='Label', y='Packets', data=packets_frame)
    plt.show()

    plt.title('Average number of transmitted bytes for different categories')
    sns.barplot(x='Label', y='Bytes', data=bytes_frame)
    plt.show()

    plt.title('Average number of connection durations for different categories')
    sns.barplot(x='Label', y='Duration', data=duration_frame)
    plt.show()


def elbow(data):
    # the elbow graph to determine the optimal number of clusters
    dist = []
    x = data.reshape(-1, 1)
    for k in range(1, 10):
        k_means = KMeans(n_clusters=k)
        k_means.fit(x)
        dist.append(sum(np.min(cdist(x, k_means.cluster_centers_, 'euclidean'), axis=1)) / x.shape[0])

    plt.plot(range(1, 10), dist)
    plt.title('Elbow rule')
    plt.xlabel('Number of Clusters')
    plt.grid(True)
    plt.title('Elbow curve')
    plt.show()


# function to find the ordinal rank based on the Pellegrino et al. paper
def estimate_ordinal_rank(bins, col_name, dataset_clean):
    percentile = round(100 / bins)

    split_list = []

    for p in range(percentile, 99, percentile):
        rank = math.ceil((p / 100.0) * len(dataset_clean[col_name]) * 1.0)
        val = sorted(dataset_clean[col_name])[int(rank)]
        split_list.append(val)
    return split_list


def attribute_mapping(x, split_list):

    for i, s in enumerate(split_list):
        if x <= s:
            return i
    return len(split_list)


def encoding(netflow, feature_space):
    code = 0
    space_size = feature_space[0]*feature_space[1]
    for i in range(0, len(feature_space)):
        code = code + (netflow[i]) * space_size / feature_space[i]
        space_size = space_size / feature_space[i]
    return code


def discretize(dataset_clean, dataset_infected):

    # Specify the number of clusters
    elbow(np.asarray(dataset_clean['Packet']))

    # for the data from all hosts
    split_list_Packets = estimate_ordinal_rank(4, 'Packet', dataset_clean)

    # ------------------- discritize the initial dataframe -------------------

    discrete = pd.DataFrame()
    discrete['Packet'] = dataset_clean['Packet'].apply(lambda x: attribute_mapping(x, split_list_Packets))

    discrete['Protocol'] = pd.factorize(dataset_clean['Protocol'])[0]

    feature_space = [discrete[name].nunique() for name in discrete.columns[0:2]]
    discrete['code'] = discrete.apply(lambda x: encoding(x, feature_space), axis=1)
    dataset_clean['code'] = discrete['code']

    discrete['Source'] = dataset_clean['Source']
    discrete['Destination'] = dataset_clean['Destination']
    discrete['DateTime'] = dataset_clean['DateTime']

    # ------------------- discretize the infected dataframe -------------------

    discrete_infected = pd.DataFrame()
    discrete_infected['Packet'] = dataset_infected['Packet'].apply(lambda x: attribute_mapping(x, split_list_Packets))

    discrete_infected['Protocol'] = pd.factorize(dataset_infected['Protocol'])[0]

    feature_space = [discrete_infected[name].nunique() for name in discrete_infected.columns[0:2]]
    discrete_infected['code'] = discrete_infected.apply(lambda x: encoding(x, feature_space), axis=1)

    # d_discr.to_csv('discrete.csv', index=None, header=True)
    # d_discr_infected.to_csv('discrete_infected.csv', index=None, header=True)

    discrete.to_pickle('discrete.pkl')
    discrete_infected.to_pickle('discrete_infected.pkl')



def main():
    dataset = read_dataset()

    # --------write--------
    # dataset.to_pickle('dataset.pkl')

    # --------read--------
    # dataset = pd.read_pickle('dataset.pkl')

    # dataset_clean, dataset_infected = remove_bkgd_flows(dataset)

    # --------write--------
    # dataset_clean.to_pickle('dataset_clean.pkl')
    # dataset_infected.to_pickle('dataset_infected.pkl')

    # --------read--------
    dataset_clean = pd.read_pickle('dataset_clean.pkl')
    dataset_infected = pd.read_pickle('dataset_infected.pkl')


    # visualize(dataset_clean, dataset_infected)

    discretize(dataset_clean, dataset_infected)


if __name__ == "__main__":
        main()


