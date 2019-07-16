# Please note, this is not a release version yet!

# Exec Wrapper
This is a very simple executable wrapper that allows a system administrator to limit the applications that any given user shall execute.
From a security standpoint, it is not meant to be a replacement for containerization or virtualization, but it can work together with those technologies, or can be just used in a pinch when either approach might be a bit overkill for the task at hand.

## How it works
A library that contains wrappers for all standard glibc exec() functions is preloaded into the user's shell, so that any attempt to run something that is not allowed will be prevented. It not only affects the command line, but all child processes that are subsequently launched, such as Firefox or Python, for example. The user that will be have limitations will use the captive shell supplied, which will enforce the LD_PRELOAD environment to be set, thus preloading this library.
It is not foolproof, but works quite well under most circumstances and can enhance the overall security of the system, especially when used in concert with other security mechanisms.
When the user, or one of the applications that the user launches, tries to execute a disallowed application on the system, it will be denied and the event will be logged to the system log.

## Why LD_PRELOAD
This method was chosen because all that is required is this wrapper, the captive shell, and some config files, and it can be used on any conventional Linux system without the need to do any special patching or hacking to Bash, glibc, or the kernel. It can also be very easily removed when no longer desired.

## Build Requirements
All that is required to build this wrapper is any modern version of gcc and Gnu Make on the target system.

## Installation And Use Requirements
After performing a make, the root user must 'make install' so the library can be placed in /usr/local/lib (or any location of your choice).
The file /etc/ld.preload must contain a line that includes this file: /usr/local/lib/libexecwrapper.so
Any user that shall have these enforcements should use the captive shell as his/her shell, instead of /bin/bash. This can be set in /etc/passwd. It is not a requirement, but it will help ensure that the environment variable gets set.
If the captive shell is not used, then it is up to the administrator to make sure that LD_PRELOAD environment variable is set in the user's .bashrc, .bash_profile, or whatever is used to set the user's environment upon login or sudo, ssh, etc.
