Welcome
===

The purpose of this GitHub repository is to be a source of ideas for anyone interested.
Clone, fork as you wish and the license requires. This project is being updated over time.


Project Background
===
My regular synchronisation, encryption and backup routines. 


Providing GPG encryption services
===

**encryption_services** is a set of utility shell scripts.

One (file_encrypter.sh), encrypts all files it's passed in a way configurable by the user, or even normals, at runtime.

Another (key_generator_and_manager.sh), makes sure all the boring CIA requirements are met when I generate a new set of encryption keys.

These are part of my own system of __specialised tools__ for my own specific workflows.

**Typical use case for file_encrypter.sh:**

Encrypt one or more files using configured parameters.

1. file_encrypter.sh is __called__ by another program which needs one or more files to be encrypted.
2. The calling program __provides__ the absolute file paths as parameters.
3. file_encrypter.sh __validates the file paths__ to make sure that the're well-formed, accessible and readable.
4. file_encrypter.sh __queries the GPG program__ to check what keys, if any are available.
5. file_encrypter.sh __gets all the values it needs to create a generic encryption command__ from a user edited configuration file.
6. file_encrypter.sh __shows user the command__ it intends to execute.
7. If user (just me) gives the ok, file_encrypter.sh __executes a specific command for each file__ and __tests the resulting postconditions__.
8. file_encrypter.sh __presents the results__ to the user.
9. file_encrypter.sh __checks whether the shred program is available__ to the user and if so, __offers to shred the original plaintext files__.
10. file_encrypter.sh returns control to the calling program.

**Typical use case for key_generator_and_manager.sh:**

Backup changes to encryption keyrings, revocation certificates etc... to locations from which they could be sync'd and stored safely for Confidentiality, Integrity and Availability. 

---


Many thanks to :octocat:


