# MIT License
#
# Copyright (c) 2019 Art Perry
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

CC = gcc
CCOPTS = -O2 -Wall
SHOPTS = -fPIC -shared
EXEOPTS = -fPIE
LNKOPTS = -ldl

LIBNAME = libexecwrapper.so
LIBPATH = /usr/local/lib
LIBFULL = ${LIBPATH}/${LIBNAME}

CSHELL = cbash
CSHELLPATH = /usr/local/bin
CPATHFULL = ${CSHELLPATH}/${CSHELL}

all: ${LIBNAME} ${CSHELL}

${LIBNAME}:
	${CC} ${CCOPTS} ${SHOPTS} -o ${LIBNAME} exec_wrapper.c ${LNKOPTS}

${CSHELL}:
	${CC} ${CCOPTS} ${EXEOPTS} -o ${CSHELL} captive_shell.c

install: ${LIBNAME} ${CSHELL}
	cp ${LIBNAME} ${LIBPATH}
	cp ${CSHELL} ${CSHELLPATH}
	chown root:root ${LIBFULL} ${CSHELLPATH}
	chmod 755 ${LIBFULL} ${CSHELLPATH}

uninstall:
	rm -fv ${LIBFULL} ${CSHELL}

clean:
	rm -fv ${LIBNAME} ${CSHELL}
