import pandas as pd
import random
import collections
import matplotlib.pyplot as plt
import numpy as np

def frequent_IPs(dataset, num):

    all_IPs=[]

    for index, row in dataset.iterrows():
        if row.Source != '147.32.84.165':
            all_IPs.append(row.Source)
        if row.Destination != '147.32.84.165':
            all_IPs.append(row.Destination)
    result = collections.Counter(all_IPs).most_common(num)
    #return (counter.most_common(k), ips)
    return result, all_IPs

def main():
    infected_dataset = pd.read_pickle('infected_dataset.pkl')
    TenMostFrequentIPs, all_IPs = frequent_IPs(infected_dataset, 10)
    print(TenMostFrequentIPs)

    #distribution of ips
    for ip in TenMostFrequentIPs:
        print('number of connections:', ip[1], 'percentile', ip[1]*100.0/len(infected_dataset))



    ###### reservoir sampling
    for reservoir_size in range(50, 1050, 50):
        for index, row in infected_dataset.iterrows():
            rand = random.uniform(0, 1)
            infected_dataset.set_value(index, 'randomNum', rand)

        sorted_dataset = infected_dataset.sort_values(['randomNum'], ascending=[True])
        sample = sorted_dataset[0:reservoir_size]
        sample = sample.reset_index(drop=True)
        # print(sample)
        reservoir_TenMostFrequentIPs, all_ip = frequent_IPs(sample, 10)
        print('=======> Value of reservoir:', reservoir_size)
        print('Top 10:', reservoir_TenMostFrequentIPs)
        for ip in reservoir_TenMostFrequentIPs:
            print('Element', ip, 'percentage', ip[1]*100.0/reservoir_size, '%')



if __name__ == "__main__":
        main()
