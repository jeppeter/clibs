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

/*************************************
* get_mount_dir : to get the device mounted directory
* return value:
*           length filled in the *ppmntdir
*           0 for not mounted
* params:
*           dev  device name if NULL ,will free(*ppmntdir)
*           ppmntdir the mount directory into day
*           pmntsize the allocated size for *ppmntdir 
*************************************/
int get_mount_dir(const char* dev, char** ppmntdir,int *pmntsize);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __UX_FILEOP_H_36C20057D60A2BC5108FF8E12352DCE4__ */
