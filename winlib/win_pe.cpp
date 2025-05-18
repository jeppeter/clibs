


void* memory_load_module(void* ptr, int memsize)
{
    PIMAGE_DOS_HEADER doshdr=NULL;
    PIMAGE_NT_HEADERS nthdr = NULL;
    int ret;

    if (memsize < sizeof(*doshdr)) {
    	ret = -ERROR_INVALID_PARAMETER;
    	goto fail;
    }


    return 
fail:

	SETERRNO(ret);
	return NULL;
}