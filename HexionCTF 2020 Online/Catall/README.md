# Catall - Solution

Created by Idan ([GitHub](https://github.com/idan22moral/) / [Twitter](https://twitter.com/idan_moral))

## Description
>I hate my friend!  
He gave me this stupid binary, and he teases me with the flag.<br><br>
Can you help me defeat this challenge and get the flag?<br><br>
`ssh catall@challenges2.hexionteam.com -p 3003`<br>
Password: `hexctf`

## Solution
In this challenge we get an SSH connection to a machine.  
The machine contains a binary file (and it's source), that has the setuid-bit set.  

When running the program we see this output:
```
Usage: catall.c /tmp/<your_folder>
```
So lets do:
```sh
$ mkdir /tmp/unicorn3000
$ cd /tmp/unicorn3000
$ ~/catall .
```
And now we get the following output:
```
flag:
```
Interesting. Lets review the code.  
In the source code we see a few functions, such as `protect`, `unprotect`, `copy`, `setup`, and of course `main`.

By a quick review, we can understand that `protect` makes the flag file immutable (non-moveable, non-modifiable, non-deletable, etc.), and `unprotect` returns it back to being mutable.<br>

The `copy` function copies the file from one point to the other, and sets the read/write permissions for the owner (user) only.

The `setup` function sets the challenge up for us - meaning that it copies the flag from `~` to our temporary directory.

When (finally) looking at `main`, we see the setup of the challenge, and the protection of the flag. We can also see that the protection is disable only after the main part of the code runs.  
**It means that no race condition** (at least from what I know) **can be used to give us permissions to view that flag after the process' runtime.**

After we know those things, let's take a look at `main`:

We run on all the entries in the directory, while there is a limit of `MAX_ENTRIES` enrties (another clue that there's no race condition, since, `MAX_ENTRIES` equals only 16).
```c
...
for (i = 0; i < n && i < MAX_ENTRIES; i++)
{
```
Then we open the current file, and read it's data
```c
    if (entry->d_type == DT_REG)
    {
        printf("%s:\n", entry->d_name);
        file = fopen(file_path, "r"); // (1)

        if (file != NULL) // (2)
        {
            memset(file_content, 0, BUFSIZE);
            fread(file_content, BUFSIZE, 1, file);
        }
```
If the file's name does not contain the word "flag", we print the content of the file and zero the buffer for "extra safety".
```c
        if (!strstr(file_path, "flag")) // (3)
        {
            printf("%s\n", file_content);
            memset(file_content, 0, BUFSIZE);
        }
    }
}
...
```

The problem lays in `(1)`.
Let's read `fopen`'s manual:
> RETURN VALUE  
&emsp;Upon  successful  completion  fopen(),  fdopen() and freopen() return a  
&emsp;FILE pointer.  **Otherwise, NULL is returned and errno is set to indicate  
&emsp;the error.**

So, if we manage to make `fopen` fail, `(2)` will not run, and a new content will not be read.

The key here is the fact that this is an iterative process.
When the current file is the flag, `(2)` executes but we pass `(3)`, so the flag was read into memory, but not cleared.  
If we manage to do the opposite in the next iteration of the loop, a new content will not be read, but the existing content (the flag) will be printed! Cool!  

How can we do that?  
We can create a file with an alphabetical order larger than `flag`'s (say "g"), then we can remove the permissions to read the file (leading to `fopen` returning `NULL`).

```sh
$ pwd
/tmp/unicorn3000
$ touch g
$ chmod -r g
```

Then run the program again

```sh
$ ~/catall .
flag:
g:
hexCTF{edg3_c4ses_ar3_7he_k3y_t0_d3struct10n}

```
Yay!<br><br>

Flag: `hexCTF{edg3_c4ses_ar3_7he_k3y_t0_d3struct10n}`
