"""
A Python file intentionally filled with various issues for static analysis testing.
"""

import os
import pickle


user_input = input('Enter code: ')
result = eval(user_input)

os.system('ls ' + user_input)

with open('data.pkl', 'rb') as f:
    data = pickle.load(f)

nums = []
for i in range(100):
    nums = nums + [i]


for i in range(10):
    temp = nums.copy()


unused_var = 123

def foo():
    
    return 'done'
    print('This will never run')


nested = [[i * j for i in range(5)] for j in range(5)]


def undocumented():
    pass 