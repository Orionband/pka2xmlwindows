# PKA Tool
pka2xml but on windows and additions.  
This is mainly for instructors and those wanting to make a competition style packet tracer.

Compile using
``g++ main.cpp -o pkatool.exe -std=c++17 -O2 -lcryptopp -lre2 -lz``  

```
usage: pkatool <option> [args...]  

options:  
  -d <in> <out>   decrypt pka/pkt to xml  
  -e <in> <out>   encrypt xml to pka/pkt  
  -f <in> <out>   patch file to be opened by any PT version  
  -p <in> <out>   remove password from activity file  
  -u <in> <out>   unlock all locked features in activity file  
  -r <in> <out>   reset activity (restore initial network, reset timer)  
  -l <in> <out>   release activity (clear recent, lock, reset)  
  -x <in> <base>  extract networks (creates <base>_current.pkt, etc)  
  -nets <in>      decrypt packet tracer "nets" file  
  -logs <in>      decrypt packet tracer log file  
  --forge <out>   forge authentication file  

examples:
  pkatool -d foobar.pka foobar.xml
  pkatool -e foobar.xml foobar.pka
  pkatool -f old.pka fixed.pka
  pkatool -p pwlocked.pka pwunlocked.pka
  pkatool -u restricted.pka unrestricted.pka
  pkatool -r expired.pka reset.pka
  pkatool -l draft.pka release.pka
  pkatool -x activity.pka networks
```
added params:  
-p  
-u  
-r  
-l  
-x  

