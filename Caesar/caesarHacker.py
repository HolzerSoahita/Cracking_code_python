# Caesar Cipher Hacker


def CaesarHacker(message='', SYMBOLS='ABCDEFGHIJKLMNOPQRSTUVWXYZaäbcçdeéèéëfghiïjklmnoöpqrstuüùvwxyz1234567890 !?.\'"`~@#$%^&*()§_°+-=[]{}|;:<>,\/'):
    """
        Function to hack caesar algorithm.
        Two arguments :
        - message : words encrypted
        - SYMBOLS : letter possible
    """

    # Loop through every possible key:
    for key in range(len(SYMBOLS)):

        translated = ''

        # Loop through each symbol in message:
        for symbol in message:
            if symbol in SYMBOLS:
                symbolIndex = SYMBOLS.find(symbol)
                translatedIndex = symbolIndex - key

                # Handle the wrap-around:
                if translatedIndex < 0:
                    translatedIndex = translatedIndex + len(SYMBOLS)

                # Append the decrypted symbol:
                translated = translated + SYMBOLS[translatedIndex]

            else:
                # Append the symbol without encrypting/decrypting:
                translated = translated + symbol

        # Display every possible decryption:
        print('Key #%s: %s' % (key, translated))


if __name__ == "__main__":
    message = 'est4&t4&w!&4mj3m5&wm44hrm)'
    CaesarHacker(message)
