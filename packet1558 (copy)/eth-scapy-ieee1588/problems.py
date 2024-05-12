def swap_case(s):

    for symbol in range(len(s)):
        if s[symbol].isalpha() and s[symbol].isupper():
            s[symbol] = s[symbol].lower()
        elif s[symbol].isalpha() and s[symbol].islower():
            s[symbol] = s[symbol].upper()
            
    return s 

result = swap_case("hej.Hur")
print(result)