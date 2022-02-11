# autorecon

Autorecon automates tools and techniques to find subdomains.
In addition to amass, subfinder, sublist3r and assetfinder, this tool uses zone transfer and check crt.sh website to gather more subdomains.
Autorecon uses httpx to recognize alive subdomains.



**INSTALL:**
```
git clone https://github.com/xbforce/autorecon.git
cd autorecon/
sudo cp autorecon.sh /usr/local/bin/
```

Use the following command to install the requirements:
```
cat requirements.txt | xargs sudo apt-get install -y
```

Then you need to install sponge from moreutils. Sponge saves modified file without redirecting them to another file.
For example, instead of ```$ sort -u -d myfile.txt > tmp_file.txt and $ mv tmp_file.txt myfile.txt``` we can do this: ```$ sort -u -d myfile.txt | sponge myfile.txt```

```
git clone git://git.joeyh.name/moreutils
cd moreutils/
gcc sponge.c -o sponge
sudo cp sponge /usr/local/bin/
```

There is another tool named httpx:
```
git clone https://github.com/projectdiscovery/httpx
cd httpx/
```
Read its README file and install it.


**USAGE:**
You need to make a file which contains inscope domains. Your file name will be used in the directory name, so it is better to not use extensions. This is because you be able to make more than one file in case you have many targets and you want to split them to different inscope files. 
Also when you make the file, avoid using protocols, slash or asterisk (start).
This is the ***wrong*** format and should not be put into inscope_domains.txt:
```
https://example.com
http://example.com/
example.com/
*.example.com/
```

Inscope targets should be written as the following:
```
example.com
target.org
```

The Usage would be:
```
kali@kali# autorecon.sh channel1
kali@kali# autorecon.sh channel2
```


Also users are able to make a list of outscope subdomains to dictate the tool to exclude those subdomains. It does not matter which domains the subdomain is for, all outscope subs should be in one file.
You need to avoid using protocols, slash and asterisc(star) for outscope_subdomains.txt file:

**Wrong format:**
```
https://image.target.org/
http://mail.target.org
login.target.org/
*.videos.target.org
```

**Right format:**
```
mail.target.org
image.target.org
demo.example.com
```

In this case the usage would be:
```
kali@kali# autorecon channel1 outscope_subdomains.txt
```
