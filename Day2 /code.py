mylist= [number for number in range(2, 21) if number % 2 == 0]

for i in range( 2,21):
    if i % 2 == 0:
        mylist.append(i)
        
print (mylist)
