# I Can Haz Proof?

Note: so far only tested on MacOS and Ubuntu.

First of all, you need an old version of clang: 3.6.x, 3.7.x or
3.8.x. At the time of writing, MacPorts clang-3.6 does not work
completely and the default Ubuntu clang is 3.8.

You can find it [here](http://llvm.org/releases/download.html). Or you can use MacPorts. Or ```apt```.

Then you need [SAW](http://saw.galois.com/builds/nightly/) (I used the
12/12/16 version) and [Z3](https://github.com/Z3Prover/z3/releases on MacOS).

Now, configure OpenSSL in a form useful to SAW:

    $ export PATH=${PATH}:<path to SAW binaries>:<path to Z3 binaries>:<path to LLVM tools>
    $ CC=<path to clang> ./config enable-saw -I<path to SAW header files>

Then, you can either build and test as normal (there is a test 90-test_proof
that runs the proofs), or if you want to keep to minimums, do this:

    $ make build_generated && make -j 40 build_proof_formulas
    $ make test TESTS=test_proof V=1
