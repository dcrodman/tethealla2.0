tethealla2.0
============

Continued development and port of Sodaboy's Tethealla PSOBB server to *nix systems.

Build Instructions
============

At this point in time, tethealla2.0 is only being written for *nix systems (though with a
little creativity, it will probably work with Cygwin). The build system uses CMake, which
can be used to generate project files for an IDE (I'm using Xcode) or to generate Makefiles
which can be compiled using GNU Make. 

To build from source:

    git clone ...
    cd tethealla2.0  
    mkdir build  
    cd build  
    cmake .. # you can add -G to specify your generator  

From there you can either run make to build everything or use whatever application you
generated the build files for. You should see one library (libtethealla.a) and (eventually)
three server executables - patch_sever, login_server, and ship_server. Each should be run
individually and configured with the instructions provided...as soon as I write them. And
figure out what configuration they need.