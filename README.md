Welcome
===

The purpose of this GitHub repository is to be a source of ideas for anyone interested.
Feel free to download or fork any of the work contained here. This project is being updated over time.

Providing gpg encryption services
===

**encryption_services** will use be used as part of my current obsession with building my own system of __specialised tools__.
Nothing too sophisticated for now, certainly not anything to be used outside of administering by own personal systems and networks.

**Use Case:**

Well, this is the the one I'm basing development on for now, although I can already imagine there's gonna be loads more scenarios - Who *doesn't* need a bit of encryption now and again...?


1. encryption_services is __called__ by another program which needs a file encrypted.
2. The program __provides__ all the relevant parameters.
3. encryption_services __does tests__ to check that all necessary preconditions exist ok.
4. encryption_services __shows user the command(s)__ it intends to execute.
5. If user (just me) gives the ok, encryption_services __executes the command(s)__ and __tests the resulting postconditions__.
6. encryption_services __presents the results__ to the user.




Project Background
===
I initially wanted to create a small script (called public_key_backup) just to run as part of my regular synchronisation, encryption and backup routines. During these routines the script would copy encryption keys, revocation certificates etc... to locations from which they could be stored safely for Confidentiality, Integrity and Availability. It was as I was about to write some encryption functionality into another script that I realised that I may need a program that specialised in handling encryption jobs. So, here it comes...

---

>**Getting creative** by solving problems.

>That's the purpose of this project.

Thankyou :octocat:


