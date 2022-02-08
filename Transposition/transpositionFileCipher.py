# Transposition Cipher Encrypt/Decrypt File
# https://www.nostarch.com/crackingcodes (BSD Licensed)

import time
import os
import sys
from transposition_encrypt_decrypt import encryptMessage, decryptMessage


def TranspositionFileCipher(inputFilename, outputFilename, myKey=10, myMode='encrypt'):
    """
        Encrypt a file with transpostion algorithm. 
        Four arguments : 
        - inputFilename : Path of input file 
        - outputFilename : Path of output file
        - myKey : key of the transposition algorithm
        - myMode : 'encrypt' or 'decrypt' 
    """

    # If the input file does not exist, then the program terminates early:
    if not os.path.exists(inputFilename):
        print('The file %s does not exist. Quitting...' % (inputFilename))
        sys.exit()

    # If the output file already exists, give the user a chance to quit:
    if os.path.exists(outputFilename):
        print('This will overwrite the file %s. (C)ontinue or (Q)uit?' %
              (outputFilename))
        response = input('> ')
        if not response.lower().startswith('c'):
            sys.exit()

    # Read in the message from the input file:
    fileObj = open(inputFilename)
    content = fileObj.read()
    fileObj.close()

    print('%sing...' % (myMode.title()))

    # Measure how long the encryption/decryption takes:
    startTime = time.time()
    if myMode == 'encrypt':
        translated = encryptMessage(myKey, content)
    elif myMode == 'decrypt':
        translated = decryptMessage(myKey, content)
    totalTime = round(time.time() - startTime, 2)
    print('%sion time: %s seconds' % (myMode.title(), totalTime))

    # Write out the translated message to the output file:
    outputFileObj = open(outputFilename, 'w')
    outputFileObj.write(translated)
    outputFileObj.close()

    print('Done %sing %s (%s characters).' %
          (myMode, inputFilename, len(content)))
    print('%sed file is %s.' % (myMode.title(), outputFilename))


# the main() function.
if __name__ == '__main__':
    inputFilename = 'frankenstein.txt'
    outputFilename = 'frankenstein.encrypted.txt'
    myKey = 10
    myMode = 'encrypt'  # set to 'encrypt' or 'decrypt'
    TranspositionFileCipher(inputFilename, outputFilename, myKey, myMode)
