# Simple Substitution Cipher Hacker
# https://www.nostarch.com/crackingcodes (BSD Licensed)

from simpleSubHackerFunction import hackSimpleSub, decryptWithCipherletterMapping


def simpleSubHacking():
    message = 'Sy l nlx sr pyyacao l ylwj eiswi upar lulsxrj isr sxrjsxwjr, ia esmm rwctjsxsza sj wmpramh, lxo txmarr jia aqsoaxwa sr pqaceiamnsxu, ia esmm caytra jp famsaqa sj. Sy, px jia pjiac ilxo, ia sr pyyacao rpnajisxu eiswi lyypcor l calrpx ypc lwjsxu sx lwwpcolxwa jp isr sxrjsxwjr, ia esmm lwwabj sj aqax px jia rmsuijarj aqsoaxwa. Jia pcsusx py nhjir sr agbmlsxao sx jisr elh. -Facjclxo Ctrramm'

    # Determine the possible valid ciphertext translations:
    print('Hacking...')
    letterMapping = hackSimpleSub(message)

    # Display the results to the user:
    print('Mapping:')
    print(letterMapping)
    print()
    print('Original ciphertext:')
    print(message)
    print()
    print('Copying hacked message to clipboard:')
    hackedMessage = decryptWithCipherletterMapping(message, letterMapping)
    print(hackedMessage)


if __name__ == '__main__':
    simpleSubHacking()
