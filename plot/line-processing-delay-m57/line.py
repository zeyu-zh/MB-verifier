import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import csv
import matplotlib.patches as mpatches
import numpy as np

# need sorted data
with open('initial_pktLog3459.csv', 'r') as ac:
    reader = csv.DictReader(ac)
    size_ac_reality01 = [row['len-m'] for row in reader]
x1 = [float(size_ac_reality01[n]) for n in range(len(size_ac_reality01))]

with open('initial_pktLog3459.csv', 'r') as ac:
    reader = csv.DictReader(ac)
    time_ac_reality01 = [row['time'] for row in reader]
y1 = [float(time_ac_reality01[n])/1000 for n in range(len(time_ac_reality01))]


with open('improved_pktLog3459.csv', 'r') as veridpi:
    reader = csv.DictReader(veridpi)
    size_veridpi_reality01 = [row['len-m'] for row in reader]
x2 = [float(size_veridpi_reality01[n]) for n in range(len(size_veridpi_reality01))] 

with open('improved_pktLog3459.csv', 'r') as veridpi:
    reader = csv.DictReader(veridpi)
    time_veridpi_reality01 = [row['time'] for row in reader]
y2 = [float(time_veridpi_reality01[n])/1000 for n in range(len(time_veridpi_reality01))]


first_index = 0
x3 = []
y3 = []
for i in range(len(x1)-1):
    if x1[i] != x1[i+1]:
        x3.append(x1[i])
        y = np.median(y1[first_index:i+1])
        y3.append(y)
        first_index = i

x1 = []
y1 = []
for i in range(len(x3)):
    if y3[i] < 150:
        x1.append(x3[i])
        y1.append(y3[i])

first_index = 0
x4 = []
y4 = []
for i in range(len(x2)-1):
    if x2[i] != x2[i+1]:
        x4.append(x2[i])
        y = np.median(y2[first_index:i+1])
        y4.append(y)
        first_index = i


x2 = []
y2 = []
for i in range(len(x4)):
    if y4[i] < 150:
        x2.append(x4[i])
        y2.append(y4[i])


fig = plt.figure()

plt.rcParams['xtick.direction'] = 'in'
plt.rcParams['ytick.direction'] = 'in'
plt.grid(linestyle='None')

plt.ylabel("Processing time (us)", fontsize = 14)
plt.xlabel("Packet size (bytes)", fontsize = 14)

plt.plot(x1, y1, 'r', label = 'Baseline')
plt.plot(x2, y2, 'b', label = 'VeriDPI')

plt.legend(loc='upper left', fontsize=13)




plt.show()

# pdf = PdfPages('process-delay.pdf')
# pdf.savefig(bbox_inches='tight')
# pdf.close()
# plt.close()

