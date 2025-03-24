# MD5 Crackme
Simple CPU MD5 cracker.

## Building
You will need `openssl-dev`/`openssl-devel` to build.

```bash
git clone https://github.com/LNDF/md5-cracker.git
cd md5-cracker
mkdir build
cd build
cmake ..
make
```

## Usage
After building, go to the build directory and run it like this:

```bash
./md5-crackme <hash to crack>
```