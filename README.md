Welcome
===

The purpose of this GitHub repository is to be a source of ideas for anyone interested.
Feel free to download or fork any of the work contained here. This project is being updated over time.

Providing GPG encryption services
===

**encryption_services** is a set of utility shell scripts, to use be used as part of my current obsession with building my own system of __specialised tools__ for my own specific workflows.
Nothing too sophisticated for now, certainly not anything to be used outside of administering by own personal systems and networks.

**Use Case for "file_encrypter.sh":**

Need to encrypt one or more files using configured parameters.

Well, this is the one on which I'll base development for now, although I can already imagine there's gonna be loads more scenarios - Who *doesn't* need a bit of encryption now and again...?


1. encryption_services is __called__ by another program which needs one or more files to be encrypted.
2. The calling program __provides__ the absolute file paths as parameters.
3. encryption_services __validates the file paths__ to make sure that the're well-formed, accessible and readable.
4. encryption_services __queries the GPG program__ to check what keys, if any are available.
5. encryption_services __gets all the values it needs to create a generic encryption command__ from the user.
6. encryption_services __shows user the command__ it intends to execute.
7. If user (just me) gives the ok, encryption_services __executes a specific command for each file__ and __tests the resulting postconditions__.
8. encryption_services __presents the results__ to the user.
9. encryption_services __checks whether the shred program is available__ to the user and if so, __offers to shred the original plaintext files__.
10. encryption_services returns control to the calling program.




Project Background
===
I initially just wanted to create a small script (called public_key_backup) to run as part of my regular synchronisation, encryption and backup routines. During these routines the script would copy any changes to encryption keyrings, revocation certificates etc... to locations from which they could be sync'd and stored safely for Confidentiality, Integrity and Availability. However, as I was about to write some encryption functionality into *another* script, I realised that it might be an idea to have a program that specialises in handling encryption jobs. So, here it comes...

---

>**Getting creative** by solving problems.

>That's the purpose of this project.

Many thanks to :octocat:


