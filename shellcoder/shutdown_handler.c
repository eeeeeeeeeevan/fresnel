// shutdown handler for persistence soontm

struct sh_iovec {
    void *iov_base;
    long iov_len;
};

struct sh_uio {
    struct sh_iovec *uio_iov;
    int uio_iovcnt;
    long uio_offset;
    long uio_resid;
    int uio_segflg;
    int uio_rw; // UIO_WRITE = 1 
    void *uio_td;
};

struct sh_args {
    long (*openat)(void*, long, const char*, int, int, int);
    long (*close)(void*, long);
    long (*pwritev)(void*, long, void*, long);

    void *td;
    char *path;
    void *data;
    long len;
    struct sh_uio uio;
    struct sh_iovec iov;
};

void shutdown_handler (struct sh_args* a, int howto)
{
    a->iov.iov_base = a->data;
    a->iov.iov_len = a->len;
    a->uio.uio_iov = &a->iov;
    a->uio.uio_iovcnt = 1;
    a->uio.uio_offset = 0;
    a->uio.uio_resid = a->len;
    a->uio.uio_segflg = 2;
    a->uio.uio_rw = 1;
    a->uio.uio_td = a->td;

    long fd = a->openat(a->td, -100, a->path, 514, 511, 0755);
    if (fd < 0)
        return;
    a->pwritev(a->td, fd, &a->uio, 0);
    a->close(a->td, fd);
}
