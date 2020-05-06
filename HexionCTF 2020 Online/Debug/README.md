# Debug - Solution

Created by Yarin ([GitHub](https://github.com/CmdEngineer) / [Twitter](https://twitter.com/CmdEngineer_))


> **Note:**  
The challenge wasn't added to the CTF in the end because using gunicorn on it will disable Flask's Debug mode.  
Runing it without gunicorn was possible, but then Flask will crash due to the fact that Flask's technical limits.  
Also - The server will need a reset when the PIN in the
challenge was guessed too many times.  
Bottom line - the challenge did not fit in a large-scale CTF.


## Description

Check out my first Flask app!

I gave it to my friend, and he told me that my web skills are really poor.
He also said that he found a super secret file under `/flag`.

Can you use this knowledge to exploit my app?

http://challenges2.hexionteam.com:2000

## Solution

You start with a welcoming page at `/welcome.html` \
If you try navigating to a different page you will get a Flask Error Page

![Image Error](assets/flask_error.png)

As you can see Debug mode is on we can try to request a shell by going to `/console` but it requests for a PIN code.

![Image Error](assets/pin_code.png)

We need to get the pin code. Bruteforce is not allowed. \
We can view some of the source in the flask error page by clicking on the error line. 
```py
@app.route("/<filename>")
def filesystem(filename):
    if "flag" not in filename.lower():
        return send_file(filename, mimetype="text")
 
if __name__ == "__main__":
    handler = TimedRotatingFileHandler("error.log", 's', 30, backupCount=1)
    old_factory = logging.getLogRecordFactory()
```
We can see that we can take any file we want except the flag. In addition the `error.log` file contains log record from Flask this can be useful to break the PIN because the PIN is printed out on the standard output of the shell

![Image Error](assets/error_pin.png)

Now we can get a console and run `open("flag", "r").read()` and get the flag.

Flag: `hexCTF{d0nt_us3_d3bug_1n_pr0duct1on}`
