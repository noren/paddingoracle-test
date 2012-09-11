paddingoracle-test
==================

Implementation of a padding oracle and a padding oracle attack against
it to teach myself on this kind of attack, perhaps it helps someone to
get a better understanding about it ;-)

The program encrypts a given text with a PKCS#5 padding and provides a
function which is this padding oracle. The main program decrypts the
text using only this oracle.

Afterwards a given text is encrypted without knowledge of the key by
usage of the padding oracle.
