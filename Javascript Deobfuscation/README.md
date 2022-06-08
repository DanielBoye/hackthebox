# Javascript Obfuscation
---
## List over encoders

Does the job: https://obfuscator.io/ 

Tutorial shows:
https://beautifytools.com/javascript-obfuscator.php

Not tried:
https://utf-8.jp/public/jjencode.html
https://utf-8.jp/public/aaencode.html

For fun: http://www.jsfuck.com/ 

## To find out what the javascript does 

https://jsconsole.com/

## Javascript Minifier (krymper koden sammen)

https://www.toptal.com/developers/javascript-minifier

## To make the code pretty

https://prettier.io/playground/
https://beautifier.io/

---
# Deobfuscate Javascript

http://www.jsnice.org/

Tip: We should click on the options button next to the "Nicify JavaScript" button, and de-select "Infer types" to reduce cluttering the code with comments.

Tip: Ensure you do not leave any empty lines before the script, as it may affect the deobfuscation process and give inaccurate results.

---
# Decoding strange blocks of text

## Base64

Spotting Base64

base64 encoded strings are easily spotted since they only contain alpha-numeric characters. However, the most distinctive feature of base64 is its padding using = characters. The length of base64 encoded strings has to be in a multiple of 4. If the resulting output is only 3 characters long, for example, an extra = is added as padding, and so on.
<br>

To encode any text into base64 in linux, we just echo our text and pipe it to base64
```
echo https://www.hackthebox.eu/ | base64
``` 
<br>

To decode it we just add a -d at the end. The command looks like this now
```
echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d
``` 

## Hex

Spotting Hex

Any string encoded in hex would be comprised of hex characters only, which are 16 characters only: 0-9 and a-f. That makes spotting hex encoded strings just as easy as spotting base64 encoded strings.

To encode any text into hex in linux, we can use the xxd -p command
```
echo https://www.hackthebox.eu/ | xxd -p
``` 
<br>

To decode it we just add a -r at the end. The command looks like this now
```
echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | base64 -d -r
``` 

## Caesar/Rot13

Spotting Caesar/Rot13

Even though this encoding method makes any text looks random, it is still possible to spot it because each character is mapped to a specific character. For example, in rot13, http://www becomes uggc://jjj, which still holds some resemblances and may be recognized as such.

There isn't a specific command in Linux to do rot13 encoding. However, it is fairly easy to create our own command to do the character shifting:
```
echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
``` 
<br>

We can use the same previous command to decode rot13 as well:
```
echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
``` 
---

Another option to encode/decode rot13 would be using an online tool, like https://rot13.com/

# Other Types of Encoding

If you stumble over a new type of encoding. Try https://www.boxentriq.com/code-breaking/cipher-identifier to identify the encoding method.




