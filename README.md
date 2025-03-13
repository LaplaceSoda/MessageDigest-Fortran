# MessageDigest-Fortran
A Fortran module for computing message digests like MD5, SHA256 and so on using the OpenSSL library.
## Dependencies
The module depends on the OpenSSL library. 
## Usage
To use MessageDigest-Fortran within your fpm project, add the following to your fpm.toml file:
```
[dependencies]
MessageDigest-Fortran = { git = "https://github.com/LaplaceSoda/MessageDigest-Fortran.git" }
```
## Example
The module provides a single function `digest` that computes the message digest of a given string. 
```
program main
    use MessageDigest
    implicit none
    character(100) :: string = "test"
    print *, digest("md5", trim(string))
    print *, digest("sha256", trim(string))
    print *, digest("SM3", trim(string))
end program main
```