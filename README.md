# async_wake exploit by @i41nbeer

iOS 11.1.2 kernel exploit and PoC local kernel debugger by @i41nbeer

This is my attempt to learn more about the iOS kernel and exploit development.
I'll try keep at it and add bits as I learn more. 

## Changes

* Adds support for iPad mini 2 wifi 
* Adds support for iPhone6 (actually shares symbols with iPod6g)
* Adds temoporary root
* Reads /etc/master.passwd as PoC

## Thanks

I wouldn't have even gotten started if not for [@cji](https://twitter.com/cji). I recommend anyone wanting to start exploring this PoC read his [blog post](https://medium.com/@cji_/hunting-for-ios-kernel-symbols-e48a446bb00)

The technique for getting root was taken from the work done by:

* Abraham Masri @cheesecakeufo [https://gist.github.com/iabem97/d11e61afa7a0d0a9f2b5a1e42ee505d8](https://gist.github.com/iabem97/d11e61afa7a0d0a9f2b5a1e42ee505d8)
* @benjibobs [https://github.com/benjibobs/async_wake](https://github.com/benjibobs/async_wake)

I've tried to comment the above work with my understanding and what I've learned in the process. If I've got something fundamentaly wrong please let me know!




