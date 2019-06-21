import pandas as pd

lines = [line.rstrip('\n') for line in open('capture20110811.pcap.netflow.labeled')]
columns = ['Date_flow', 'Start', 'Duration', 'Protocol', 'Source', 'Destination', 'Packet', 'Bytes', 'Label']
data = []
for line in lines[1:]:
    lists = line.split("\t")
    spl = ' '.join(lists).split()
    data.append([spl[0], spl[1], spl[2], spl[3],
                 spl[4].split(":")[0], spl[6].split(":")[0], spl[9], spl[10], spl[12]])

dataset = pd.DataFrame(data, columns=columns)


# dataset.to_csv('dataset.csv')
dataset.to_pickle('dataset.pkl')


infected_host = '147.32.84.165'
infected_dataset = dataset.loc[(dataset['Source'] == infected_host) | (dataset['Destination'] == infected_host)]
infected_dataset = infected_dataset.reset_index()



# infected_dataset.to_csv('infected_dataset.csv')
infected_dataset.to_pickle('infected_dataset.pkl')
