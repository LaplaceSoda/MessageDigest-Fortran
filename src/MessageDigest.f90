module MessageDigest
    use, intrinsic :: iso_c_binding
    implicit none
    private

    interface
        ! MD5
        function EVP_md5() bind(C, name="EVP_md5")
            import :: c_ptr
            type(c_ptr) :: EVP_md5
        end function
        ! SHA1
        function EVP_sha1() bind(c, name="EVP_sha1")
            import :: c_ptr
            type(c_ptr) :: EVP_sha1
        end function EVP_sha1
        ! SHA224
        function EVP_sha224() bind(c, name="EVP_sha224")
            import :: c_ptr
            type(c_ptr) :: EVP_sha224
        end function EVP_sha224
        ! SHA256
        function EVP_sha256() bind(c, name="EVP_sha256")
            import :: c_ptr
            type(c_ptr) :: EVP_sha256
        end function EVP_sha256
        ! SHA384
        function EVP_sha384() bind(c, name="EVP_sha384")
            import :: c_ptr
            type(c_ptr) :: EVP_sha384
        end function EVP_sha384
        ! SHA512
        function EVP_sha512() bind(c, name="EVP_sha512")
            import :: c_ptr
            type(c_ptr) :: EVP_sha512
        end function EVP_sha512

        function EVP_MD_CTX_new() bind(c, name="EVP_MD_CTX_new")
            import :: c_ptr
            type(c_ptr) :: EVP_MD_CTX_new
        end function EVP_MD_CTX_new

        function EVP_DigestInit_ex(ctx, md, impl) bind(c, name="EVP_DigestInit_ex")
            import :: c_ptr, c_int
            type(c_ptr), value :: ctx, md, impl
            integer(c_int) :: EVP_DigestInit_ex
        end function EVP_DigestInit_ex

        function EVP_DigestUpdate(ctx, data, len) bind(c, name="EVP_DigestUpdate")
            import :: c_ptr, c_int, c_size_t
            type(c_ptr), value :: ctx, data
            integer(c_size_t), value :: len
            integer(c_int) :: EVP_DigestUpdate
        end function EVP_DigestUpdate

        function EVP_DigestFinal_ex(ctx, md, len) bind(c, name="EVP_DigestFinal_ex")
            import :: c_ptr, c_int, c_size_t
            type(c_ptr), value :: ctx, md, len
            integer(c_int) :: EVP_DigestFinal_ex
        end function EVP_DigestFinal_ex

        subroutine EVP_MD_CTX_free(ctx) bind(c, name="EVP_MD_CTX_free")
            import :: c_ptr
            type(c_ptr), value :: ctx
        end subroutine EVP_MD_CTX_free
    end interface

    public :: digest

contains

    function digest(algorithm, string) result(hex_hash)
        character(len=*), intent(in) :: algorithm       !! MD5, SHA1, SHA224, SHA256, SHA384, SHA512
        character(len=*), target, intent(in) :: string  !! input string
        character(len=:), allocatable :: hex_hash

        type(c_ptr) :: ctx, md
        integer(c_int) :: status
        character(kind=c_char), allocatable, target :: hash_buf(:)
        integer :: hash_length, i

        ! 选择算法并确定哈希长度
        select case (lower(trim(algorithm)))
        case ('md5')
            md = EVP_md5()
            hash_length = 16
        case ('sha1')
            md = EVP_sha1()
            hash_length = 20
        case ('sha224')
            md = EVP_sha224()
            hash_length = 28
        case ('sha256')
            md = EVP_sha256()
            hash_length = 32
        case ('sha384')
            md = EVP_sha384()
            hash_length = 48
        case ('sha512')
            md = EVP_sha512()
            hash_length = 64
        case default
            error stop "Unsupported algorithm: "//algorithm
        end select
        if (.not. c_associated(md)) error stop "Failed to get "//algorithm//" method"

        ctx = EVP_MD_CTX_new()
        if (.not. c_associated(ctx)) error stop "Failed to create context"

        status = EVP_DigestInit_ex(ctx, md, C_NULL_PTR)
        if (status /= 1) error stop "Digest init failed"

        status = EVP_DigestUpdate(ctx, c_loc(string), len(string, c_size_t))
        if (status /= 1) error stop "Digest update failed"

        allocate (hash_buf(hash_length))
        status = EVP_DigestFinal_ex(ctx, c_loc(hash_buf), C_NULL_PTR)
        if (status /= 1) error stop "Digest final failed"

        call EVP_MD_CTX_free(ctx)

        allocate (character(len=2*hash_length) :: hex_hash)
        write (hex_hash, '(*(Z2.2))') (ichar(hash_buf(i), kind=1), i=1, hash_length)
    end function digest

    function lower(str) result(lc_str)
        character(len=*), intent(in) :: str
        character(len=len(str)) :: lc_str
        integer :: i, iv

        do i = 1, len(str)
            iv = iachar(str(i:i))
            if (iv >= 65 .and. iv <= 90) then  ! A-Z
                lc_str(i:i) = achar(iv + 32)
            else
                lc_str(i:i) = str(i:i)
            end if
        end do
    end function lower

end module MessageDigest
