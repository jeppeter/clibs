#ifndef __UX_FILEOP_H_36C20057D60A2BC5108FF8E12352DCE4__
#define __UX_FILEOP_H_36C20057D60A2BC5108FF8E12352DCE4__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

#define  STDOUT_FILE_FLAG         1
#define  STDERR_FILE_FLAG         2

int read_file_whole(char* infile,char** ppoutbuf,int *bufsize);
int read_stdin_whole(int freed,char** ppoutbuf,int *bufsize);
int write_file_whole(char* outfile,char* poutbuf,int outsize);
int write_out_whole(int flag,char* poutbuf,int outsize);
int realpath_safe(char* path, char** pprealpath, int *psize);
int read_offset_file(char* infile,unsigned long long offset,char* pbuf,int bufsize);
int write_offset_file(char* outfile,unsigned long long offset,char* pbuf,int bufsize);

/*************************************
* dev_get_mntdir : to get the device mounted directory
* return value:
*           length filled in the *ppmntdir
*           0 for not mounted
*           < 0 for error
* params:
*           dev  device name if NULL ,will free(*ppmntdir)
*           ppmntdir the mount directory to fill
*           pmntsize the allocated size for *ppmntdir 
*************************************/
int dev_get_mntdir(const char* dev, char** ppmntdir,int *pmntsize);

/*************************************
* path_get_mntdir : to get he deivce to get the most directory for mount
* return value:
*           length filled in *ppmntdir
*           < 0 for error
* params:
*           path path to search
*           ppmntdir the mount directory to fill
*           pmntsize the allocated size for *ppmntdir 
*************************************/
int path_get_mntdir(const char* path, char** ppmntdir,int *pmntsize);

/*************************************
* mntdir_get_dev : to get the device for the mountdir
* return value:
*           length filled in *ppdev
*           < 0 for error
* params:
*           path path to search
*           ppdev the devices to fill
*           pdevsize the allocated size for *ppdev 
*************************************/
int mntdir_get_dev(const char* path,char** ppdev,int *pdevsize);

/*************************************
* mntdir_get_fstype : to get the fstype for the mountdir
* return value:
*           length filled in *ppfstype
*           < 0 for error
* params:
*           path path to search
*           ppfstype the devices to fill
*           pfssize the allocated size for *ppfstype
*************************************/
int mntdir_get_fstype(const char* path,char** ppfstype,int *pfssize);


/*************************************
* cp_file : to copy file from srcfile to dstfile
*************************************/
int cp_file(char* srcfile, char* dstfile);


/*************************************
* mkdir_p : to mkdir -p
*************************************/
int mkdir_p(const char* dname, int mask);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_FILEOP_H_36C20057D60A2BC5108FF8E12352DCE4__ */
