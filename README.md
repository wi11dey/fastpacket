# netbox

A general and simple ptrace-based sandbox which can prevent programs from reaching 
any external site, while still allowing loopback connections on 
localhost without slowdown, as well as fork-bomb protections on number 
of children spawned.

## Usage
```
$ make
$ ./sandbox <sandbox jail directory> <user id to execute sandboxed application as>
```

## Tests
See [`guest_dir`](https://github.com/wi11dey/netbox/tree/main/guest_dir) for an example app that stress tests the sandbox with fork-bombing and attempts to connect to the outside world. All attempts are correctly foiled.
