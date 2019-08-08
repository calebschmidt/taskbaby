# Final Writeup

## Introduction

For this final writeup, I will be going over, step-by-step, my working
through and solving of a few challenges on **Hack the Box**. Hack the Box
is a pentesting and cyber security capture-the-flag learning environment.
It allows users to test and hone their offensive security skills by
completing various challenges for points. These challenges fall within
several categories, and for my time on Hack the Box, I found myself drawn
largely to the crypto scenarios.

Quite honestly, I was surprised that I ended up focusing so heavily on
decoding encrypted messages, but through a combination of circumstances
this ended up being my primary area of focus. In particular, the first
challenge I tried, in order to "get my feet wet" was a relatively simple
crypto challenge. This whet my appetite for more. I felt that this kind
of challenge was approachable; the goal was clear and the realm of possible
techniques, while still large, was somewhat more focused than the other
kinds of challenges I attempted.

Though crypto was my primary focus, it was not the only area I explored.
I also completed challenges under forensics and web, and attempted another
labelled OSINT (whose challenges I relate below). Overall I felt this
smattering of challenges gave me a good feel for the kinds of problems
encountered by security professionals, and piqued my interest in further
developing my own pentesting skills.

But how did I even get started? Hack the Box is not simply a site one can
sign up for and immediately start hacking. Indeed, even being able to sign
up turns out to be the first challenge faced.

## Invite

Navigating to `hackthebox.eu`, I see the login link in the top right corner.
Seeing no other link labelled "sign up" or anything similar, I assume that
on the login page will be somewhere where new users can register. I assumed
wrong. I was presented with the page below, welcoming me and asking for an
invite code. The message informing me that I should feel free to hack my
way in is a good hint as to what is expected. It makes sense that a
pentesting website would make you hack your way in. This immediately gave
me a feel for the spirit and expectations of Hack the Box.


Where to begin? I assume that since this is a website for learning how to
hack, it can't be too difficult. My first thought is to crack open the
browser's inspector and see if anything is hidden on the page.


The markup all looked fairly standard from what little I know of web
development (HTML, JavaScript, and CSS), so that appeared to be a dead end.
My next thought was to see what JavaScript exists on the page. Previously,
when trying to enumerate all globally available functions on a page in
JavaScript for debugging a database project, I stumbled on a neat little
snippet that does exactly that. The snippet can be found at: 
https://davidwalsh.name/global-variables-javascript. Running this code in
the console, we see some interesting things.


It looks like there are two interesting functions defined in this page's
JavaScript: `verifyInviteCode` and `makeInviteCode`. Looking at them in the
console we can see that `verifyInviteCode` takes a code as an argument, but
`makeInviteCode` is simply an AJAX call to the `/api/invite/how/to/gengrate`
API endpoint. That sounds exactly like what I am looking for.


Calling `makeInviteCode()` in the console I received the following response.


At this point I was a bit hasty and simply plopped the string in the
response into the invite code box and tried it. It was, unsurprisingly,
invalid. Had I taken a few seconds more to examine the response I would
seen that it is clearly labelled as Base64 encoded. Thankfully, decoding
Base64 is trivial. My main weapon of choice for encoding/decoding issues
is the fantastic Cyber Chef, a tool open-sourced by the UK's GCHQ (basically
their equivalent of the NSA). However, I already had Notepad++ (another
wonderful and underrated tool) open, and it has the ability to decode Base64
built in. Decoding the string I got the following.


This was clear confirmation that I was on the right track. And thankfully,
POSTing to an API endpoint is fairly easy. In my day job I build lots of
Python programs that interact with various RESTful APIs, and one key tool
that I use for debugging and testing is the Advanced Rest Client browser
plugin. Firing it up and POSTing to the `/api/invite/generate` I received
another encoded response.

Having learned my lesson from my earlier hastiness, I immediately decode
this as Base64.

This looks like an invite code! Plugging it in, I successfully enter Hack
the Box and am able to register.


## You Can Do It!

Once registered, the first challenge I attempted was a crypto challenge
named "You Can Do It!". I chose it not just for it's positive tone and
affirmation of my abilities, but because it was labelled as easy by most
of the members who had completed it. This being my first few minutes in
Hack the Box, I was not looking to be overly ambitious; I simply wanted
to complete a challenge that gave me a good feel for how the site and
challenges worked. A 10-point challenge seemed just the answer.


There was essentially no prompt for this challenge, so I simply downloaded
it and unzipped the file. I then used `cat` to examine the contents. 


Looking at the text, this file didn't look like it was encoded, simply
scrambled. I supposed that must have been why it was only worth 10 points.
The word "YOU" jump out at me, looking at the beginning of the string and
skipping to every third letter. Doing this (literally just scanning along
with my finger), I could also see the word "SEE". I realized that the next
step was simply to find the pattern and extract the unscrambled string.


Initially I tried doing some fancy iterating over the string in Python.
I tried turning the string into a list and popping letters, but after a few
tries moved on to a different approach. I tried putting the string's
characters into a deque, but after a bit of fiddling it struck me that a
real-world hacker, when confronted with a challenge of this (small) scale,
is not going to waste time doing this the fancy way. They will concentrate
on what works; pragmatism reigns in offensive computer security. So, 
instead, I just wrote it out and unscrambled it manually. It was inelegant,
but highly effective for this trivial problem.


Excellent. Manually extracting the unscrambled string seemed to work. I only
encountered on small hiccup: I initially entered it as human-readable (with
spaces between words). After getting an error when submitting this flag,
I realized that I should submit it exactly as it was extracted. Simply
removing the spaces and re-entering it worked. This simply emphasized to me
that for these challenges, Hack the Box wants the _exact_ flag as presented,
without any cleaning up. First challenge down!


## Bank Heist

I enjoyed the feel of the first crypto challenge, so I decided to try my
hand at another. I liked the more puzzle like feel of unscrambling the text,
and I wanted to see what other kinds of challenges there were. Scanning
through the other possibilities, I chose Bank Heist. Still feeling some
timidity, I only wanted to escalate the challenge to one ranked somewhat
more difficult and worth 20 points.


The idea behind bank heist is that you have captured a suspect in a bank
robbery, and on their phone you have discovered a message that needs
decoding. Significantly, the challenge prompt mentions that this is a flip
phone. This struck me as odd initially, but eventually this proved to be the
crucial clue in my completion of the challenge.


As before, I began by downloading, unzipping, and examining the contents.
It is essentially a string with several groups of digits.


What was odd was the numerous repetitions of the digits. Additionally,
the grouping and use of punctuation seemed to indicate that each group of
digits was a word. This hunch was strengthened when I realized that even
the relative (not absolute) lengths of the groups of digits seemed to
reflect how English sentences are structured -- that is, there were longer
groupings often connected by shorter groups, parallelling the use of
normal-length words with short prepositions and conjunctions.


With these observations, particularly that the digits are often repeated in
succession, I realized tha a simple substitution cipher was unlikely. This
ruled out things like Caeser and Vigenere ciphers. I spent a while looking
through the other encoding and encryption possibilities in Cyber Chef, but
nothing seemed to fit. Finally, the initial prompt struck me as possibly
bing an indicator. I then literally Googled "flip phone encryption" and
immediately found some promising leads. After looking into the T9 Mobile
Cipher for SMS, I decided that it was not the right answer. The ciphertext
I had for this challenge was not a close enough match. So I kept digging
through my search results. Eventually I stumbled on Multi-Tap Cipher for
SMS, and a French website with a decoder for this encoding at:
https://www.dcode.fr/multitap-abc-cipher. The examples for this encoding 
looked much like what I had for the challenge, so I decided to use the
decoder on my ciphertext.


Excellent! Multi-Tap Cipher for SMS did the trick. At least most of the
trick. There was still a line at the end of the message that looked
encoded. I reran this portion and tried many of different encodings for
I had tried earlier on the whole message, but to no avail. The "GO TO
PARIS" portion seemed to be a clue. For quite a while I was convinced that
this meant that it had been encoded using a Vignere cipher. Taking this
tack, I fired up Cyber Chef and then tried many keys, including "PARIS",
"FRANCE", "BANK", "MONEY", and "HACKTHEBOX". All with no success. I
realized that this approach was not going to be a productive one; I was
thrashing about for a solution rather than systematically going about
solving the challenge. I then began trying other substitution ciphers.
I chose to limit my search to simple substitution ciphers, as the text
appeared likely to be the product of simple substitution. The word lengths
were normal and each word was solely composed of uppercase letters.


Eventually I just got lucky. Using Cyber Chef, I was working my way through
the various encodings. After trying all the ROT possibilities, and several
other substitution schemes, I eventually tried Atbash. Immediately I was
presented with the answer. I was gratified, but curious. I had never heard
of Atbash substitution, so I did some research and discovered that it is a
substitution cipher originally designed to encode Hebrew. However, it has
since been modified to encode Latin script. Essentially, it takes the
alphabet and maps it to its reverse (e.g., a becomes z and vice versa).


It took some time and a bit of floundering, but eventually I solved the
challenge. There was a large dose of luck, but that is likely to always
be the case in the real-world, open-ended computer security and defense
problems we may face day to day.


## Took the Byte

For my final challenge, I settled on a forensics challenge. Given the material
that has been covered over the past several weeks, this seemed like a
natural place to try out some of the forensics skills that I had gained.
Though I dodn't know it at the outset, this challenge ended up being very
similar to those above, but with a slight twist.


As before, I began the challenge by downloading and unzipping the file for
this challenge. Unlike the previous challenge, the prompt was not particularly
helpful (though it made much more sense in retrospectr, after the completion
of the challenge).


The file itself appeared to be a binary, which given the little information
I had to go on from the prompt made sense. Therefore, my first step was to
inspect a hexdump of the contents. Examining the hexdump, there did not seem
to be a whole lot for me to go on. I didn't spit any immediately obvious
patterns.


As there was not much to go on, I next turned to my trusty friend Cyber Chef.
I tried (without much aim or guidance) a few of the various decoding options,
but nothing seemed to make much sense. I realized that I was once again
thrashing without a definite plan, so I paused to consider a better way
forward on this challenge.


After reflecting on the challenge a bit, it struck me that if this is indeed
binary, then binary operations are the ones I should be investigating. Once
again, Cyber Chef came to the rescue. It hosts a number of common binary
operations that can be applied to strings and files (with a convenient drag
and drop interface). I then began purposefully applying various binary
operations to the provided file.


The first binary operation listed in CyberChef is XOR. This makes sense, as
the XOR operation is often used in encryption schemes. Immediately this got
my mind working and sparked some hope in me that this was the right tack to
take. So I started XORing various keys against the data. But once again, as
in when I suspected a Vigenere cipher was being used in the Bank Heist
challenge, I realized that simply guessing keys was not a practical way to
go about this. Conveniently, the very next operation listed under XOR in
CyberChef is XOR Brute Force. That sounds exactly like what I need.


Loading up the XOR Brute Force operation, I see that I still have to input
a key length. However, I decided to leave it set to the defaults and work
the length up, depending on how long it took to process. For a key length
of 1 (a single byte) there are 255 possible keys. CyberChef enumerates all
of these and prints them out. I began scanning the output, and most of it
appeared to simply be garbage values. However, the very last entry (for
a key of `ff`) produced something interesting.


While this still appears to be mostly incomprehensible, the value
`password.txt` is clearly visible. At this point I was stumped for a bit.
It seemed that I was on the right path, but I wasn't sure what the next step
should be. It was ony after Googling portions of this string that I had a
breakthrough. It turns out that the initial `PK..` represents the so-called
"magic bytes" indicating a zip file. Excellent! Adding unzip to the
recipe in CyberChef we get the flag. Success!


## Conclusion


Overall I found the challenges on Hack the Box to be rather engaging and
interesting. As I mentioned at the outset, I was surprised at how my
challenges ended up focusing primarily on encoding and decryption. For this
experience alone I found the challenges worthwhile; I would likely have
never forced myself to try to decrypt or decode messages of these kinds.
Additionally, it feels somewhat empowering. Though my completion of the
three challenges above only puts me at, according to Hack the Box, 16.6% of
the way to "Script Kiddie", I feel much more open to tackling such
security-related challenges in the future.
