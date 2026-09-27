# Intentional structural clone fixture

def calculate_regular_discount(price, rate):
    tax = price * 0.05
    discount = price * rate
    total = price + tax - discount
    return total

def calculate_vip_discount(price, rate):
    tax = price * 0.05
    discount = price * rate
    total = price + tax - discount
    return total
