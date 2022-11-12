import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from matplotlib import cm
import matplotlib.pyplot as plt
import matplotlib.tri as mtri
import numpy as np

with open("time_log",'r') as file:
    lines = file.readlines()
    n_list = set()
    k_list = set()
    time_list = []
    for line in lines:
        tmp = line.split('  ')
        n_list.add(int(tmp[0]))
        k_list.add(int(tmp[1]))
        time_list.append(float(tmp[2]))
    
X=np.sort(np.array(list(n_list)))
Y=np.sort(np.array(list(k_list)))
print(X)
print(Y)
Z=np.array(time_list).reshape(3,5).T
print(Z)
fig = plt.figure()
ax = plt.axes(projection='3d')
ax.contour3D(X, Y, Z, 50, cmap='binary')
ax.set_xlabel('x')
ax.set_ylabel('y')
ax.set_zlabel('z')
plt.imshow(res3)
plt.show()