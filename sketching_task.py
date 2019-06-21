import mmh3
import math
from sampling_task import frequent_IPs
import pandas as pd
import operator
import timeit
import random



class CountMinSketch:

    def __init__(self, w, d):
        self.size = w * d
        self.w = w
        self.hash_count = d
        self.cm_array = [[0] * w for i in range(d)]

    def add(self, string):
        for seed in range(self.hash_count):
            result = mmh3.hash(string, seed) % self.w
            self.cm_array[seed][result] += 1

    def point(self, string):
        minimum = 9999999
        for seed in range(self.hash_count):
            result = mmh3.hash(string, seed) % self.w
            if self.cm_array[seed][result] < minimum:
                minimum = self.cm_array[seed][result]
        return minimum

def grid_search(e, ips, infected_dataset):

    # grid seach for different w and d
    count = 0
    for epsilon in [0.0001, 0.001, 0.005, 0.01, 0.1]:
        for delta in [0.0001, 0.001, 0.005, 0.01, 0.1]:

            # calculate the w, d
            w = round(e / epsilon)
            d = round(math.log(1 / delta))

            # construct the matrix with the correct dimensions
            count_min_matrix = CountMinSketch(int(w), int(d))

            # add each ip to the matrix
            for ip in ips:
                count_min_matrix.add(ip)

            # find frequency and store it to cm_res
            count_min = {}
            for ip in ips:
                count_min[ip] = count_min_matrix.point(ip)

            # sort them according to their value to find the 10 most frequent ones
            sorted_count_min = sorted(count_min.items(), key=operator.itemgetter(1), reverse=True)

            ten_sorted_count_min = sorted_count_min[0:10]

            print("Iteration", count)

            for ip in ten_sorted_count_min:
                print('Element', ip, 'percentage', ip[1] * 100.0 / len(infected_dataset), '%')

            count += 1


def calculate_time(ips, infected_dataset):

    # ------------Min-Wise time estimation-------------
    start_minWise = timeit.default_timer()

    k = 5000
    for index, row in infected_dataset.iterrows():
        # begin by setting a random value at each row
        a = random.uniform(0, 1)
        infected_dataset.set_value(index, 'rn', a)

    sort_infections = infected_dataset.sort_values(['rn'], ascending=[True])
    sel_k = sort_infections[0:k]
    sel_k = sel_k.reset_index(level=0, drop=True)
    most_freq_minWise, ips_minWise = frequent_IPs(sel_k, 10)

    stop_minWise = timeit.default_timer()
    minWise_time = stop_minWise - start_minWise

    # ------------Count-Min Sketch time estimation------------
    start_countMin_sketch = timeit.default_timer()

    epsilon = 0.0001
    delta = 0.0001
    e = 2.718281828
    w = round(e / epsilon)
    d = round(math.log(1 / delta))

    # construct the matrix with the correct dimensions
    count_min_matrix = CountMinSketch(int(w), int(d))

    # store ip addresses
    for ip in ips:
        count_min_matrix.add(ip)

    # estimate frequency
    count_min = {}
    for ip in ips:
        count_min[ip] = count_min_matrix.point(ip)

    # sort frequencies according to their value
    sorted_count_min  = sorted(count_min.items(), key=operator.itemgetter(1), reverse=True)

    #  find the 10 most frequent ones
    ten_sorted_count_min = sorted_count_min[0:10]

    stop_countMin_sketch = timeit.default_timer()

    count_min_time = stop_countMin_sketch - start_countMin_sketch

    print(minWise_time, count_min_time)


def main():

    e = 2.718281828
    infected_dataset = pd.read_pickle('infected_dataset.pkl')
    TenMostFrequentIPs, ips = frequent_IPs(infected_dataset, 10)
    grid_search(e, ips, infected_dataset)
    calculate_time(ips, infected_dataset)


if __name__ == "__main__":
        main()
