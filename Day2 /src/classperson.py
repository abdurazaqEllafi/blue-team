class Person:
    def __init__(self, name, age, city):
       
        self.name = name
        self.age = age
        self.city = city

    def print_details(self):
        print(f"Hi, I'm {self.name}, {self.age} years old from {self.city}")

person1=Person("abdurazaq", 27 , "misrata")
person1.print_details()


