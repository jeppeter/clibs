#ifndef __WIN_BASE64_H_D96624A48FC1E891D941C47A81BE5355__
#define __WIN_BASE64_H_D96624A48FC1E891D941C47A81BE5355__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus*/

int encode_base64(unsigned char* pbuffer,int insize, char* pencbuf,int outsize);
int decode_base64(char* pencbuf, int insize,unsigned char* pbuffer, int outsize);

#ifdef __cplusplus
};
#endif /* __cplusplus*/

#endif /* __WIN_BASE64_H_D96624A48FC1E891D941C47A81BE5355__ */
