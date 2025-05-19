

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

typedef struct __image_mem_list {
    void* m_ptr;
    struct __image_mem_list* m_next;
} image_mem_list_t,*pimage_mem_list_t;

typedef struct __image_mem  {
    pimage_mem_list_t m_blockmem;
} image_mem_t,*pimage_mem_t;

void __free_image_mem(pimage_mem_t* ppmem)
{
    if (ppmem && *ppmem) {
        pimage_mem_t pmem = *ppmem;

        if (pmem->m_blockmem) {
            pimage_mem_list_t plist = pmem->m_blockmem;
            pimage_mem_list_t pnext;
            while(plist != NULL) {
                pnext = plist->m_next;
                plist->m_next = NULL;
                free(plist);
                plist = NULL;
                plist = pnext;
            }
            pmem->m_blockmem = NULL;
        }
    }
}

addr_t __align_mem_up(addr_t endaddr, size_t alignsize)
{
    addr_t retaddr = (endaddr + alignsize - 1);
    addr_t alignmask = ~((addr_t)(alignsize - 1));
    return (retaddr & alignmask);
}

pimage_mem_t __alloc_image_mem()
{
    pimage_mem_t pmem = NULL;
    pmem = malloc(sizeof(*pmem));
    if (pmem == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(pmem,0,sizeof(*pmem));

    return pmem;
fail:
    __free_image_mem(&pmem);
    SETERRNO(ret);
    return NULL;
}

void* memory_load_module(void* ptr, size_t memsize)
{
    PIMAGE_DOS_HEADER doshdr=NULL;
    PIMAGE_NT_HEADERS nthdr = NULL;
    uint8_t* curptr=NULL;
    int ret;
    int i;
    PIMAGE_SECTION_HEADER section;
    size_t optionsize;
    addr_t sectionend = 0;
    pimage_mem_t pmem = NULL;
    SYSTEM_INFO* psysinfo =NULL;
    addr_t lastendsection = 0;

    pmem = __alloc_image_mem();
    if (pmem == NULL) {
        GETERRNO(ret);
        goto fail;
    }


    if (memsize < sizeof(*doshdr)) {
    	ret = -ERROR_INVALID_PARAMETER;
    	goto fail;
    }

    doshdr = (PIMAGE_DOS_HEADER) ptr;
    if 

    if (doshdr->e_magic != IMAGE_DOS_SIGNATURE) {
        ret = -ERROR_BAD_EXE_FORMAT;
        goto fail;
    }

    if (memsize < doshdr->e_lfanew + sizeof(*nthdr)) {
        ret = -ERROR_BAD_EXE_FORMAT;
        goto fail;
    }
    curptr = ptr + doshdr->e_lfanew;
    nthdr = (PIMAGE_NT_HEADERS) curptr;
    if (nthdr->Signature != IMAGE_NT_SIGNATURE) {
        ret = -ERROR_BAD_EXE_FORMAT;
        goto fail;
    }

    if (nthdr->FileHeader.Machine != HOST_MACHINE) {
        ret = -ERROR_BAD_EXE_FORMAT;
        goto fail;
    }

    if ((nthdr->OptionalHeader.SectionAlignment & 1 ) != 0) {
        ret = -ERROR_BAD_EXE_FORMAT;
        goto fail;
    }


    section = IMAGE_FIRST_SECTION(nthdr);
    optionsize = nthdr->OptionalHeader.SectionAlignment;
    for (i=0;i<nthdr->FileHeader.NumberOfSections;i++, section ++) {
        addr_t endsection;
        if (section->SizeOfRawData == 0) {
            endsection = section->VirtualAddress + optionsize;
        } else {
            endsection = section->VirtualAddress + section->SizeOfRawData;
        }
        if (lastendsection < endsection) {
            lastendsection = endsection;
        }
    }

    psysinfo = malloc(sizeof(*psysinfo));
    if (psysinfo == NULL) {
        GETERRNO(ret);
        goto fail;
    }
    memset(psysinfo, 0, sizeof(*psysinfo));
    GetNativeSystemInfo(psysinfo);

    alignend = __align_mem_up(nthdr->OptionalHeader.SizeOfImage, psysinfo->dwPageSize);
    if (alignend != __align_mem_up(lastendsection,psysinfo->dwPageSize)) {
        ret = -ERROR_BAD_EXE_FORMAT;
        ERROR_INFO("alignend 0x%llx != __align_mem_up(0x%llx,0x%lx)", alignend, lastendsection, psysinfo->dwPageSize);
        goto fail;
    }

    


    if (psysinfo) {
        free(psysinfo);
    }
    psysinfo = NULL;


    return  pmem;
fail:
    if (psysinfo) {
        free(psysinfo);
    }
    psysinfo = NULL;

    __free_image_mem(&pmem);
	SETERRNO(ret);
	return NULL;
}