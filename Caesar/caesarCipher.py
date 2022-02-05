# Caesar Cipher

def CaesarCipher(message='', key=3, mode='encrypt'):
    """
        Function to crypt message with Caesar Cipher.
        Three arguments:
        - message : text to encrypt or decrypt
        - key : code of caesar algorithm
        - mode : "encrypt" or "decrypt"  
    """

    # All possible symbol:
    SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZaäbcçdeéèéëfghiïjklmnoöpqrstuüùvwxyz1234567890 !?.\'"`~@#$%^&*()§_°+-=[]{}|;:<>,\/'

    # message to encrypted/decrypted:
    translated = ''

    for symbol in message:
        if symbol in SYMBOLS:
            symbolIndex = SYMBOLS.find(symbol)

            # Perform encryption/decryption:
            if mode == 'encrypt':
                translatedIndex = symbolIndex + key
            elif mode == 'decrypt':
                translatedIndex = symbolIndex - key

            # Handle wrap-around, if needed:
            if translatedIndex >= len(SYMBOLS):
                translatedIndex = translatedIndex - len(SYMBOLS)
            elif translatedIndex < 0:
                translatedIndex = translatedIndex + len(SYMBOLS)

            translated = translated + SYMBOLS[translatedIndex]
        else:
            # Append the symbol without encrypting/decrypting if it exists:
            translated = translated + symbol
    return translated


# Test the Caesar cipher
if __name__ == "__main__":
    cryptedMessage = CaesarCipher('This is my secret message.', 13, 'encrypt')
    print(cryptedMessage)
    print(CaesarCipher(cryptedMessage, 13, 'decrypt'))
