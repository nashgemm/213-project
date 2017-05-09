### 213-Project by Ajuna, Gemma and Kathryn

Our project is an extension on the password cracker that we started in the
213 lab but ran on the GPU. Given an eight character password, we will use
our various approaches to let you know how fast/difficult it is to crack
your password. We have three different approaches: comparing against a list
of popular passwords, adding numbers to the end of various dictionary
length words and brute force.

In order to run the program, you first have to run `make`.
After that, you just run the program using the command `./cracker` and
follow the given instructions to enter your sample test password. Look over
the sample run below to see an example.

### Sample Run

Ajuna@ritchie$ make
nvcc -arch sm_20 -g -I/usr/include/SDL2 -D_REENTRANT -o cracker cracker.cu -L/usr/lib/x86_64-linux-gnu -lSDL2 -lcrypto

Ajuna@ritchie$ ./cracker
Enter in your test password: passw0rd

APPROACH ONE: Look in popular passwords file 
Password has been found on the GPU by popularPasswords. It is passw0rd 
It took 0 seconds and 302 milliseconds to find your password.
Ajuna@ritchie$ ./cracker
Enter in your test password: republic

APPROACH ONE: Look in popular passwords file 

APPROACH TWO: Add numbers to the end of dictionary words 
Password has been found on the GPU by popularPasswords. It is republic 
It took 0 seconds and 102 milliseconds to find your password.
Ajuna@ritchie$ ./cracker
Enter in your test password: michelle

APPROACH ONE: Look in popular passwords file 
Password has been found on the GPU by popularPasswords. It is michelle 
It took 0 seconds and 52 milliseconds to find your password.


Ajuna@ritchie$ ./cracker
Enter in your test password: patience

APPROACH ONE: Look in popular passwords file 

APPROACH TWO: Add numbers to the end of dictionary words 
Password has been found on the GPU by popularPasswords. It is patience 
It took 0 seconds and 111 milliseconds to find your password.
Ajuna@ritchie$ ./cracker
Enter in your test password: patient123

APPROACH ONE: Look in popular passwords file 

APPROACH TWO: Add numbers to the end of dictionary words 
Password has been found on the GPU by adding numbers to the end of a dictionary word. It is patient1 
It took 0 seconds and 112 milliseconds to find your password.
Ajuna@ritchie$ ./cracker
Enter in your test password: patmos23

APPROACH ONE: Look in popular passwords file 

APPROACH TWO: Add numbers to the end of dictionary words 
Password has been found on the GPU by adding numbers to the end of a dictionary word. It is patmos23 
It took 0 seconds and 124 milliseconds to find your password.
Ajuna@ritchie$ ./cracker
Enter in your test password: aasdsaad

APPROACH ONE: Look in popular passwords file 

APPROACH TWO: Add numbers to the end of dictionary words 

APPROACH THREE: Brute Force 
Password has been found on the GPU by bruteForce. It is aasdsaad 
It took 5 seconds and 582 milliseconds to find your password.
