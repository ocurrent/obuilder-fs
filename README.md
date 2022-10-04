obuilder-fs
-----------

The File System for OBuilder x MacOS -- it's sole purpose is to redirect calls heading to some path (e.g. `/usr/local`) to a directory pointed to 
by a symbolic link inside another folder (e.g. `/data/scoreboard/`) using the `UID` of the Fuse Context of the caller (e.g. `/data/scoreboard/<uid> ~~> /Volumes/tank/result/<hash>`). To make this clearer here is a series of steps this FS should take: 


```
(1) Mount obuilder-fs to /usr/local with scoreboard /data/scoreboard 

(2) User mac705 makes a call like: ls /usr/local

(3) obuilder-fs intercepts and calls: readlink on /data/scoreboard/705 

(4) successful readlink returns: /Volumes/tank/result/abcde12345

(5) obuilder-fs list the directories inside /Volumes/tank/result/abcde12345
```

The CLI tool is very simple as expects `<scoreboard-path> <mount-point> <fuse-args-like-allow-other>...`. 

A typical usage would be:

```
sudo obuilderfs ~/scoreboard /usr/local -o allow_other
```
