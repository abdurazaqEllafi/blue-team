class bankAccount:
    def __init__(self, balance=0):
        self.balance = balance

    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            print(f"Deposited: {amount}, New Balance: {self.balance}")
            return True
        return False


    def withdraw(self, amount):
        if 0 < amount <= self.balance:
            self.balance -= amount
            print(f"Withdrawn: {amount}, New Balance: {self.balance}")  
            return True
        return False

    def get_balance(self):
        return self.balance
        print(f"Current Balance: {self.balance}")
        
account1 = bankAccount(1000)
print("Initial Balance:", account1.get_balance())
account1.deposit(500)
print("Balance after deposit:", account1.get_balance())
account1.withdraw(200)
print("Balance after withdrapwal:", account1.get_balance())
account1.withdraw(1500) 
print("error : amount of withdraw more than your balance , your account balance is ", account1.get_balance())