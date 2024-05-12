#!/usr/bin/env python3
#coding: utf-8

import matplotlib.pyplot as plt
import numpy as np
import os



# text_file_name = os.environ.get("FILE_NAME")
text_file_name = "/home/labuser/Documents/kand/Timed_Results/TestTime_nr_6010.txt"
# test_duration = int(os.environ.get("DURATION"))
test_duration = 3

with open(f'{text_file_name}', 'r') as file:
    # Read all lines into a list
    data = file.readlines()


# Extracting data into separate lists
offsets = []
frequencies = []
delays = []



for item in data:
    parts = item.split()
    try:
        if 'offset' in parts:
            offset_index = parts.index('offset') + 1
            offsets.append(int(parts[offset_index]))
        if 'freq' in parts:
            freq_index = parts.index('freq') + 1
            frequencies.append(int(parts[freq_index]))
        if 'delay' in parts:
            delay_index = parts.index('delay') + 1
            delays.append(int(parts[delay_index]))
    except IndexError:
        pass

# Create a linspace array with 99 data points and interval 0.1
# time_list = np.linspace(0, 5,len(offsets))

scaled_offsets = [offset *(10**-9) for offset in offsets]
# time_passed = np.linspace(0, (test_duration*60), len(offsets))
time_passed = np.linspace(0,(test_duration*60), len(offsets))

#a, b = -50*(10**-6), 50*(10**-6)
# a, b = -50, 50

plt.figure(figsize=(10, 7))
plt.plot(time_passed, scaled_offsets, marker='o', linestyle='-')
#plt.ylim(bottom=a)
#plt.ylim(top=b)
# plt.scatter(time_passed, scaled_offsets, marker='o')
plt.title('Offset vs. Time')
plt.xlabel('Time(s)')
plt.ylabel('Offset(s)')
plt.grid(True)
plt.show()
# file_number = ""
# for char in text_file_name:
#     if char.isdigit():
#         file_number += char

# i = 0
# while True:
#     i += 1
#     filename = f"Trial_nr_{file_number}"
#     print(filename)
#     newname = f"./Test_pngs/{filename}"
#     if os.path.exists(newname):
#         continue
#     else:
#         plt.savefig(newname)
#         break
# exit()

