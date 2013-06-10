def nums(path='/'):
    import os
    sum = 0
    for i,j,k in os.walk(path):
        sum += len(k)
    return sum



n = nums()
print n
