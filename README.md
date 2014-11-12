tethealla2.0
============

Continued development and port of Sodaboy's Tethealla PSOBB server to *nix systems. 
Probably ought to rename this at some point as it's evolved into more of a complete 
reimplementation, borrowing parts (and inspiration) from Tethealla, Newserv 
(http://www.fuzziqersoftware.com), and Sylverant (http://sylverant.net).

Installation Requirements
============

	cmake
    iconv
    jansson
    polarssl
    MySQL Server
    MySQL Connector C

Each can be found at the following locations:  
CMake: http://www.cmake.org/cmake/resources/software.html  
iconv: https://www.gnu.org/software/libiconv/  
Jansson: http://www.digip.org/jansson/  
PolarSSL: https://polarssl.org/sha-256-source-code  
MySQL Server: http://dev.mysql.com/downloads/mysql/  
MySQL C Connector: http://dev.mysql.com/doc/connector-c/en/connector-c-installation-source.html  

Build Instructions
============

At this point in time, tethealla2.0 is only being written for *nix systems (though with a
little creativity, it will probably work with Cygwin). The build system uses CMake, which
can be used to generate project files for an IDE (I'm using Xcode) or to generate Makefiles
which can be compiled using GNU Make. 

To build the whole project from source:

    git clone github-provided-url
    cd tethealla2.0  
    mkdir build && cd build
    cmake ..

You can also build each project individually. For exmaple:

    mkdir build_patch && cd build_patch
    cmake ../patch_server/

From there you can either run make to build everything or use whatever application you
generated the build files for. You should see one library (libtethealla.a) and (eventually)
four server executables - patch_sever, login_server, shipgate, and ship_server. Each should be 
run individually and configured with the instructions provided...as soon as I write them. And 
figure out what configuration they need. As they are, example configuration files can be found 
in the config/ subdirectory of the project. 

Note that if you're using Xcode (or another IDE) as a generator (with the -G option) to edit 
or build the project, you may need to explicitly edit your linker's library and include paths. 
These will likely be /usr/local/lib and /usr/local/include respectively if on *nix and you 
installed the libraries to your system.