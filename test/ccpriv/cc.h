#ifndef __CC_H_CCFBC04DEFAF7233BB21A58CEA98FA77__
#define __CC_H_CCFBC04DEFAF7233BB21A58CEA98FA77__

typedef struct cc_priv_st CC_PRIV;

CC_PRIV* new_cc(int a,int b);
int get_a(CC_PRIV* pret);
int get_b(CC_PRIV* pret);
int set_a(CC_PRIV* pret,int a);
int set_b(CC_PRIV* pret, int b);
void free_cc(CC_PRIV** ppret);

#endif /* __CC_H_CCFBC04DEFAF7233BB21A58CEA98FA77__ */
