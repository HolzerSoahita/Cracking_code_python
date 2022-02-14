# Affine Cipher

from affineCipherFunction import decryptMessage


def AffineCipher():
    myMessage = """"A computer would deserve to be called intelligent if it could deceive a human into believing that it was human." -Alan Turing"""
    myKey = 2894
    myMode = 'encrypt'  # Set to either 'encrypt' or 'decrypt'.

    if myMode == 'encrypt':
        translated = decryptMessage(myKey, myMessage)
    elif myMode == 'decrypt':
        translated = decryptMessage(myKey, myMessage)
    print('Key: %s' % (myKey))
    print('%sed text:' % (myMode.title()))
    print(translated)
    print('Full %sed text copied to clipboard.' % (myMode))


# the main() function.
if __name__ == '__main__':
    AffineCipher()
